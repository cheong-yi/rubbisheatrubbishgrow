import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


def _api():
    try:
        module = importlib.import_module("rerg.git_worktree_inventory")
        return module.collect_git_worktree_inventory, module.GitInventoryError
    except (ImportError, AttributeError):
        def missing(_scope):
            raise NotImplementedError("Git worktree inventory contract is missing")
        return missing, RuntimeError


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={
            "PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", ""),
            "LC_ALL": "C", "LANG": "C", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
        },
    ).stdout.strip()


def _repo(root: Path, files: dict[str, str]) -> str:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q")
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    _git(root, "add", "--", ".")
    subprocess.run(
        [
            "git", "-c", "user.name=RERG Test",
            "-c", "user.email=rerg@example.invalid",
            "commit", "-qm", "fixture",
        ],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            **os.environ,
            "GIT_AUTHOR_DATE": "2026-09-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-09-01T00:00:00Z",
        },
    )
    return _git(root, "rev-parse", "HEAD")


def _canonical_digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()


def _paired_state(head=None, staged=b"", untracked=b"", status=b"", config=b""):
    head = b"a" * 40 + b"\n" if head is None else head
    return [
        config, head, staged, untracked, status,
        config, head, staged, untracked, status,
    ]


def _sentinel_filter_config(driver: str = "sentinel") -> bytes:
    return (
        f"filter.{driver}.clean\0"
        f"filter.{driver}.smudge\0"
        f"filter.{driver}.process\0"
        f"filter.{driver}.required\0"
    ).encode()


def _sentinel_filter_overrides(driver: str = "sentinel") -> tuple[str, ...]:
    return (
        "-c", f"filter.{driver}.clean=",
        "-c", f"filter.{driver}.smudge=",
        "-c", f"filter.{driver}.process=",
        "-c", f"filter.{driver}.required=false",
    )


def test_top_level_and_nested_scope_are_bound_and_projected(tmp_path):
    head = _repo(tmp_path, {
        "README.txt": "outside\n",
        "packages/app/src/todo/store.py": "TODO = 1\n",
        "packages/app/src/handoff/state.py": "HANDOFF = 1\n",
        "packages/app/srcish/not-in-scope.py": "NO = 1\n",
    })
    collect, _ = _api()
    top = collect(tmp_path)
    nested = collect(tmp_path / "packages/app/src")

    assert top["head_oid"] == nested["head_oid"] == head
    assert top["scope_prefix"] == ""
    assert nested["scope_prefix"] == "packages/app/src"
    assert [item["path"] for item in nested["records"]] == [
        "handoff/state.py", "todo/store.py",
    ]
    assert all("srcish" not in item["path"] for item in nested["records"])
    assert top["scope_identity_sha256"] != nested["scope_identity_sha256"]


def test_non_git_scope_fails_closed(tmp_path):
    collect, error = _api()
    with pytest.raises(error, match="TARGET_WORKTREE_BINDING"):
        collect(tmp_path)


def test_discovered_top_level_mismatch_and_scope_escape_fail(monkeypatch, tmp_path):
    module = importlib.import_module("rerg.git_worktree_inventory")
    scope = tmp_path / "scope"
    scope.mkdir()

    monkeypatch.setattr(module, "_run_git", lambda *_args, **_kwargs: b"/elsewhere\n")
    with pytest.raises(module.GitInventoryError, match="TARGET_WORKTREE_BINDING"):
        module.collect_git_worktree_inventory(scope)


def test_exact_argv_split_cwd_closed_environment_and_no_pathspec(monkeypatch, tmp_path):
    module = importlib.import_module("rerg.git_worktree_inventory")
    scope = tmp_path / "repo" / "nested"
    scope.mkdir(parents=True)
    top = scope.parent
    oid = "a" * 40
    calls = []
    state = _paired_state(
        head=(oid + "\n").encode(),
        staged=b"100644 " + b"b" * 40 + b" 0\tnested/todo.py\0",
        config=_sentinel_filter_config(),
    )
    outputs = iter([
        (str(top) + "\n").encode(), *state,
    ])
    expected_filter_overrides = _sentinel_filter_overrides()

    def fake(argv, *, cwd, config_overrides=()):
        calls.append((argv, cwd, config_overrides))
        return next(outputs)

    monkeypatch.setattr(module, "_run_git", fake)
    receipt = module.collect_git_worktree_inventory(scope)
    assert calls == [
        (("rev-parse", "--show-toplevel"), scope, ()),
        (("config", "--local", "--name-only", "-z", "--list"), top, ()),
        (("rev-parse", "--verify", "HEAD"), top, expected_filter_overrides),
        (("ls-files", "--stage", "-z", "--"), top, expected_filter_overrides),
        (("ls-files", "--others", "--exclude-standard", "-z", "--"), top, expected_filter_overrides),
        (("status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none", "--no-renames", "--"), top, expected_filter_overrides),
        (("config", "--local", "--name-only", "-z", "--list"), top, ()),
        (("rev-parse", "--verify", "HEAD"), top, expected_filter_overrides),
        (("ls-files", "--stage", "-z", "--"), top, expected_filter_overrides),
        (("ls-files", "--others", "--exclude-standard", "-z", "--"), top, expected_filter_overrides),
        (("status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none", "--no-renames", "--"), top, expected_filter_overrides),
    ]
    assert receipt["records"][0]["path"] == "todo.py"
    assert all(
        argv[-1:] == ("--",)
        for argv, _cwd, _overrides in calls
        if argv[0] in {"ls-files", "status"}
    )
    assert receipt["disabled_filter_drivers"] == ["sentinel"]
    assert receipt["filter_config_keys_sha256"] == hashlib.sha256(
        _sentinel_filter_config()
    ).hexdigest()


def test_real_popen_boundary_uses_execution_closed_argv_and_environment(
    monkeypatch, tmp_path,
):
    module = importlib.import_module("rerg.git_worktree_inventory")
    observed = {}

    def capture(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        raise OSError("stop after boundary capture")

    monkeypatch.setattr(module.subprocess, "Popen", capture)
    with pytest.raises(module.GitInventoryError, match="GIT_NONZERO"):
        module._run_git(
            ("status", "--porcelain=v1"),
            cwd=tmp_path,
            config_overrides=_sentinel_filter_overrides(),
        )

    assert observed["command"] == (
        "git", "--no-pager",
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.pager=cat",
        "-c", "pager.status=false",
        "-c", "diff.renames=false",
        "-c", "diff.renameLimit=0",
        "-c", "status.renames=false",
        "-c", "filter.sentinel.clean=",
        "-c", "filter.sentinel.smudge=",
        "-c", "filter.sentinel.process=",
        "-c", "filter.sentinel.required=false",
        "status", "--porcelain=v1",
    )
    assert observed["kwargs"]["env"] == {
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
    }
    assert observed["kwargs"]["stdin"] is subprocess.DEVNULL
    assert observed["kwargs"]["shell"] is False
    assert observed["kwargs"]["start_new_session"] is True


def test_run_git_rejects_real_nonzero_without_mocking_runner(tmp_path):
    module = importlib.import_module("rerg.git_worktree_inventory")

    with pytest.raises(module.GitInventoryError, match="GIT_NONZERO"):
        module._run_git(("definitely-not-a-git-subcommand",), cwd=tmp_path)


def test_local_filter_helpers_are_disabled_without_sentinel_side_effect(tmp_path):
    _repo(tmp_path, {
        ".gitattributes": "*.txt filter=sentinel\n",
        "tracked.txt": "before\n",
    })
    sentinel = tmp_path / "filter-executed"
    helper = tmp_path / "helper.py"
    helper.write_text(
        "import pathlib, sys\n"
        "pathlib.Path(sys.argv[1]).write_text('executed')\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n"
    )
    command = f"{sys.executable} {helper} {sentinel}"
    _git(tmp_path, "config", "--local", "filter.sentinel.clean", command)
    _git(tmp_path, "config", "--local", "filter.sentinel.smudge", command)
    _git(tmp_path, "config", "--local", "filter.sentinel.process", command)
    _git(tmp_path, "config", "--local", "filter.sentinel.required", "true")
    (tmp_path / "tracked.txt").write_text("after\n")

    collect, _ = _api()
    receipt = collect(tmp_path)

    assert not sentinel.exists()
    assert receipt["disabled_filter_drivers"] == ["sentinel"]
    assert receipt["worktree_state"] == "dirty"


@pytest.mark.parametrize(
    ("config", "reason"),
    [
        (b"filter.bad path.clean\0", "GIT_FILTER_CONFIG_MALFORMED"),
        (b"filter..clean\0", "GIT_FILTER_CONFIG_MALFORMED"),
        (b"filter." + b"a" * 65 + b".clean\0", "GIT_FILTER_CONFIG_MALFORMED"),
        (b"filter.sentinel.clean", "GIT_FILTER_CONFIG_MALFORMED"),
        (b"".join(f"filter.f{i}.clean\0".encode() for i in range(33)), "GIT_FILTER_CONFIG_LIMIT"),
    ],
)
def test_malformed_or_oversized_filter_config_discovery_fails_closed(
    monkeypatch, tmp_path, config, reason,
):
    module = importlib.import_module("rerg.git_worktree_inventory")
    scope = tmp_path / "repo"
    scope.mkdir()
    outputs = iter([
        (str(scope) + "\n").encode(),
        config,
    ])
    monkeypatch.setattr(module, "_run_git", lambda *_a, **_k: next(outputs))

    with pytest.raises(module.GitInventoryError, match=reason):
        module.collect_git_worktree_inventory(scope)


def test_changed_filter_config_discovery_fails_closed_before_receipt(
    monkeypatch, tmp_path,
):
    module = importlib.import_module("rerg.git_worktree_inventory")
    scope = tmp_path / "repo"
    scope.mkdir()
    first = [
        b"",
        b"a" * 40 + b"\n",
        b"100644 " + b"b" * 40 + b" 0\trepository_adapter.py\0",
        b"",
        b"",
    ]
    second = [
        _sentinel_filter_config(),
        *first[1:],
    ]
    outputs = iter([(str(scope) + "\n").encode(), *first, *second])
    monkeypatch.setattr(module, "_run_git", lambda *_a, **_k: next(outputs))

    with pytest.raises(module.GitInventoryError, match="GIT_FILTER_CONFIG_CHANGED"):
        module.collect_git_worktree_inventory(scope)


def test_process_group_cleanup_wait_is_bounded_after_sigkill(monkeypatch):
    module = importlib.import_module("rerg.git_worktree_inventory")
    waits = []

    class NeverReaped:
        pid = 43210

        def wait(self, *, timeout):
            waits.append(timeout)
            raise subprocess.TimeoutExpired("git", timeout)

    monkeypatch.setattr(module.os, "killpg", lambda *_args: None)
    module._terminate_group(NeverReaped())
    assert waits == [module._CLEANUP_TIMEOUT_SECONDS]


def test_bounded_runner_enforces_exit_output_timeout_and_process_group_cleanup(
    tmp_path,
):
    module = importlib.import_module("rerg.git_worktree_inventory")
    execute = module._execute_bounded
    with pytest.raises(module.GitInventoryError, match="GIT_STDOUT_LIMIT"):
        execute(
            (sys.executable, "-c", "import sys; sys.stdout.write('xx')"),
            cwd=tmp_path, stdout_limit=1, stderr_limit=1024, timeout=5,
        )
    with pytest.raises(module.GitInventoryError, match="GIT_STDERR_LIMIT"):
        execute(
            (sys.executable, "-c", "import sys; sys.stderr.write('xx')"),
            cwd=tmp_path, stdout_limit=1024, stderr_limit=1, timeout=5,
        )
    _, _, returncode = execute(
        (sys.executable, "-c", "raise SystemExit(7)"),
        cwd=tmp_path, stdout_limit=1024, stderr_limit=1024, timeout=5,
    )
    assert returncode == 7

    child_pid_file = tmp_path / "child.pid"
    script = (
        "import pathlib, subprocess, sys, time;"
        "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(p.pid));"
        "time.sleep(30)"
    )
    with pytest.raises(module.GitInventoryError, match="GIT_TIMEOUT"):
        execute(
            (sys.executable, "-c", script),
            cwd=tmp_path, stdout_limit=1024, stderr_limit=1024, timeout=0.2,
        )
    child_pid = int(child_pid_file.read_text())
    process_state = Path(f"/proc/{child_pid}/stat")
    assert not process_state.exists() or process_state.read_text().split()[2] == "Z"


def test_malformed_non_utf8_and_nul_records_fail_atomically(monkeypatch, tmp_path):
    module = importlib.import_module("rerg.git_worktree_inventory")
    scope = tmp_path / "repo"
    scope.mkdir()
    oid = "a" * 40
    malformed = [
        b"100644 " + b"b" * 40 + b" 0 missing-tab\0",
        b"100644 " + b"b" * 40 + b" 0\tbad\\path\0",
        b"100644 " + b"b" * 40 + b" 0\tbad/../path\0",
        b"100644 " + b"b" * 40 + b" 0\tbad-\xff.py\0",
        b"100644 " + b"b" * 40 + b" 0\tgood.py\0junk",
    ]
    for staged in malformed:
        outputs = iter([
            (str(scope) + "\n").encode(),
            *_paired_state(head=(oid + "\n").encode(), staged=staged),
        ])
        monkeypatch.setattr(module, "_run_git", lambda *_a, **_k: next(outputs))
        with pytest.raises(module.GitInventoryError, match="GIT_INVENTORY_MALFORMED"):
            module.collect_git_worktree_inventory(scope)


@pytest.mark.parametrize(
    ("mutation_index", "mutated"),
    [
        (2, b"c" * 40 + b"\n"),
        (3, b"100644 " + b"d" * 40 + b" 0\trepository_adapter.py\0"),
        (4, b"untracked.py\0"),
        (5, b" M repository_adapter.py\0"),
    ],
)
def test_git_inventory_requires_two_identical_state_passes_before_receipt(
    monkeypatch, tmp_path, mutation_index, mutated,
):
    module = importlib.import_module("rerg.git_worktree_inventory")
    scope = tmp_path / "repo"
    scope.mkdir()
    first_pass = [
        b"",
        b"a" * 40 + b"\n",
        b"100644 " + b"b" * 40 + b" 0\trepository_adapter.py\0",
        b"",
        b"",
    ]
    second_pass = list(first_pass)
    second_pass[mutation_index - 1] = mutated
    outputs = iter([(str(scope) + "\n").encode(), *first_pass, *second_pass])
    monkeypatch.setattr(module, "_run_git", lambda *_a, **_k: next(outputs))

    with pytest.raises(module.GitInventoryError, match="GIT_INVENTORY_CHANGED"):
        module.collect_git_worktree_inventory(scope)


def test_git_inventory_second_pass_failure_preserves_underlying_reason(
    monkeypatch, tmp_path,
):
    module = importlib.import_module("rerg.git_worktree_inventory")
    scope = tmp_path / "repo"
    scope.mkdir()
    first_pass = [
        b"",
        b"a" * 40 + b"\n",
        b"100644 " + b"b" * 40 + b" 0\trepository_adapter.py\0",
        b"",
        b"",
    ]
    calls = []

    def fake(argv, *, cwd, config_overrides=()):
        calls.append((argv, cwd))
        if len(calls) == 1:
            return (str(scope) + "\n").encode()
        if len(calls) <= 6:
            return first_pass[len(calls) - 2]
        if len(calls) == 8:
            raise module.GitInventoryError("GIT_NONZERO")
        return first_pass[len(calls) - 7]

    monkeypatch.setattr(module, "_run_git", fake)

    with pytest.raises(
        module.GitInventoryError,
        match="GIT_INVENTORY_SECOND_PASS_FAILED:GIT_NONZERO",
    ):
        module.collect_git_worktree_inventory(scope)


def test_tracked_untracked_dirty_deleted_ignored_symlink_and_submodule_policy(tmp_path):
    _repo(tmp_path, {"tracked.py": "A = 1\n", "deleted.py": "D = 1\n", ".gitignore": "ignored.py\n"})
    (tmp_path / "tracked.py").write_text("A = 2\n")
    (tmp_path / "deleted.py").unlink()
    (tmp_path / "new.py").write_text("N = 1\n")
    (tmp_path / "ignored.py").write_text("I = 1\n")
    os.symlink("tracked.py", tmp_path / "linked.py")
    _git(tmp_path, "add", "--", "linked.py")

    collect, _ = _api()
    receipt = collect(tmp_path)
    records = {item["path"]: item for item in receipt["records"]}
    assert records["tracked.py"]["status"] == " M"
    assert records["deleted.py"]["availability"] == "missing"
    assert records["new.py"]["tracking"] == "untracked"
    assert "ignored.py" not in records
    assert {item["path"]: item["category"] for item in receipt["exclusions"]}["linked.py"] == "symlink"
    assert receipt["ignore_policy"] == "git-exclude-standard"
    assert receipt["worktree_state"] == "dirty"
    assert receipt["dirty_paths"] == ["deleted.py", "linked.py", "new.py", "tracked.py"]


def test_staged_deletion_and_inside_movement_are_path_state_changes(
    tmp_path,
):
    _repo(tmp_path, {
        "deleted.py": "D = 1\n",
        "old.py": "VALUE = 1\n",
    })
    _git(tmp_path, "rm", "--", "deleted.py")
    _git(tmp_path, "mv", "--", "old.py", "new.py")

    collect, _ = _api()
    receipt = collect(tmp_path)
    records = {item["path"]: item for item in receipt["records"]}
    assert records["deleted.py"] == {
        "path": "deleted.py", "tracking": "status-only",
        "mode": None, "oid": None, "stage": None,
        "status": "D ", "availability": "missing",
    }
    assert records["old.py"] == {
        "path": "old.py", "tracking": "status-only",
        "mode": None, "oid": None, "stage": None,
        "status": "D ", "availability": "missing",
    }
    assert records["new.py"]["status"] == "A "
    assert records["new.py"]["availability"] == "available"


def test_cross_scope_staged_add_delete_fails_without_rename_classification(tmp_path):
    _repo(tmp_path, {"nested/a.py": "A = 1\n", "outside.py": "B = 1\n"})
    _git(tmp_path, "rm", "--", "outside.py")
    (tmp_path / "nested/moved.py").write_text("LOW_SIMILARITY = 'unrelated body'\n")
    _git(tmp_path, "add", "--", "nested/moved.py")
    collect, error = _api()
    with pytest.raises(error, match="CROSS_SCOPE_PATH_STATE"):
        collect(tmp_path / "nested")


def test_top_scope_low_similarity_move_copy_and_nested_inside_movement_are_not_renames(
    tmp_path,
):
    _repo(tmp_path, {
        "nested/old.py": "OLD = 1\n",
        "outside.py": "B = 1\n",
        "copied.py": "COPY = 1\n",
    })
    _git(tmp_path, "rm", "--", "outside.py")
    (tmp_path / "nested/moved.py").write_text("LOW_SIMILARITY = 'unrelated body'\n")
    (tmp_path / "copied_again.py").write_text("COPY = 1\n")
    _git(tmp_path, "mv", "--", "nested/old.py", "nested/new.py")
    _git(tmp_path, "add", "--", "nested/moved.py", "copied_again.py")

    collect, _ = _api()
    top = collect(tmp_path)
    records = {item["path"]: item for item in top["records"]}
    assert records["outside.py"]["status"] == "D "
    assert records["nested/moved.py"]["status"] == "A "
    assert records["copied_again.py"]["status"] == "A "
    assert records["nested/old.py"]["status"] == "D "
    assert records["nested/new.py"]["status"] == "A "
    assert all("R" not in item["status"] and "C" not in item["status"] for item in top["records"])


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (b"ZZ bad.py\0", "GIT_INVENTORY_MALFORMED"),
        (b"UU conflict.py\0", "GIT_UNMERGED"),
        (b"AA conflict.py\0", "GIT_UNMERGED"),
    ],
)
def test_porcelain_status_codes_are_validated_and_conflicts_are_specific(
    monkeypatch, tmp_path, status, reason,
):
    module = importlib.import_module("rerg.git_worktree_inventory")
    scope = tmp_path / "repo"
    scope.mkdir()
    outputs = iter([
        (str(scope) + "\n").encode(),
        *_paired_state(status=status),
    ])
    monkeypatch.setattr(module, "_run_git", lambda *_a, **_k: next(outputs))
    with pytest.raises(module.GitInventoryError, match=reason):
        module.collect_git_worktree_inventory(scope)


def test_scope_and_inventory_digests_are_relocation_invariant_and_sensitive(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    files = {"nested/todo.py": "TODO = 1\n"}
    _repo(first, files)
    _repo(second, files)
    collect, _ = _api()
    a = collect(first / "nested")
    b = collect(second / "nested")
    assert a["scope_identity_sha256"] == b["scope_identity_sha256"]
    assert a["inventory_sha256"] == b["inventory_sha256"]

    (second / "nested/todo.py").write_text("TODO = 2\n")
    dirty = collect(second / "nested")
    assert dirty["scope_identity_sha256"] == b["scope_identity_sha256"]
    assert dirty["inventory_sha256"] != b["inventory_sha256"]
    _git(second, "config", "--local", "filter.audit.clean", "")
    filter_configured = collect(second / "nested")
    assert filter_configured["filter_config_keys_sha256"] != dirty[
        "filter_config_keys_sha256"
    ]
    assert filter_configured["inventory_sha256"] != dirty["inventory_sha256"]
    payload = {
        key: value for key, value in b.items()
        if key not in {"inventory_sha256", "worktree_state", "dirty_paths"}
    }
    assert b["inventory_sha256"] == _canonical_digest(payload)

    _git(
        first,
        "-c", "user.name=RERG Test",
        "-c", "user.email=rerg@example.invalid",
        "commit", "--allow-empty", "-qm", "head-only change",
    )
    head_changed = collect(first / "nested")
    assert head_changed["head_oid"] != a["head_oid"]
    assert head_changed["scope_identity_sha256"] != a["scope_identity_sha256"]
    assert head_changed["inventory_sha256"] != a["inventory_sha256"]


def test_duplicate_stage_and_unmerged_records_fail(monkeypatch, tmp_path):
    module = importlib.import_module("rerg.git_worktree_inventory")
    scope = tmp_path / "repo"
    scope.mkdir()
    oid = b"b" * 40
    for staged, reason in [
        (b"100644 " + oid + b" 0\ta.py\0" + b"100644 " + oid + b" 0\ta.py\0", "GIT_INVENTORY_MALFORMED"),
        (b"100644 " + oid + b" 1\ta.py\0", "GIT_UNMERGED"),
    ]:
        outputs = iter([(str(scope) + "\n").encode(), *_paired_state(staged=staged)])
        monkeypatch.setattr(module, "_run_git", lambda *_a, **_k: next(outputs))
        with pytest.raises(module.GitInventoryError, match=reason):
            module.collect_git_worktree_inventory(scope)


def test_normal_multistage_conflict_fails_specifically_git_unmerged(
    monkeypatch, tmp_path,
):
    module = importlib.import_module("rerg.git_worktree_inventory")
    scope = tmp_path / "repo"
    scope.mkdir()
    oid = b"b" * 40
    staged = b"".join(
        b"100644 " + oid + f" {stage}\tconflict.py\0".encode()
        for stage in (1, 2, 3)
    )
    outputs = iter([
        (str(scope) + "\n").encode(),
        *_paired_state(staged=staged, status=b"UU conflict.py\0"),
    ])
    monkeypatch.setattr(module, "_run_git", lambda *_a, **_k: next(outputs))
    with pytest.raises(module.GitInventoryError) as caught:
        module.collect_git_worktree_inventory(scope)
    assert caught.value.args == ("GIT_UNMERGED",)


def test_symlink_and_submodule_stage_modes_are_metadata_only(monkeypatch, tmp_path):
    module = importlib.import_module("rerg.git_worktree_inventory")
    scope = tmp_path / "repo"
    scope.mkdir()
    oid = b"b" * 40
    staged = (
        b"120000 " + oid + b" 0\tlinked.py\0"
        + b"160000 " + oid + b" 0\tvendor/tool\0"
    )
    outputs = iter([
        (str(scope) + "\n").encode(),
        *_paired_state(staged=staged),
    ])
    monkeypatch.setattr(module, "_run_git", lambda *_a, **_k: next(outputs))
    receipt = module.collect_git_worktree_inventory(scope)
    assert receipt["records"] == []
    assert receipt["exclusions"] == [
        {"path": "linked.py", "category": "symlink"},
        {"path": "vendor/tool", "category": "submodule"},
    ]
