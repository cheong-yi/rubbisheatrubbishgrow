import base64
import copy
import hashlib
import importlib
import os
from pathlib import Path
import subprocess
import sys

import pytest

NOW = "2026-09-01T00:00:00Z"
CONTEXT = {
    "target": "hermes-static",
    "load_bearing_needs": [
        {"need_id": "need-inspect", "statement": "inspect repository adapter source"},
    ],
}


@pytest.fixture(autouse=True)
def _enclosing_git_worktree(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git", "-c", "user.name=RERG Test",
            "-c", "user.email=rerg@example.invalid",
            "commit", "--allow-empty", "-qm", "fixture root",
        ],
        cwd=tmp_path,
        check=True,
    )


def _adapter():
    try:
        return importlib.import_module("rerg.repository_target_adapter").adapt_repository_target
    except (ImportError, AttributeError):
        def missing(**_kwargs):
            raise NotImplementedError("repository target adapter contract is missing")
        return missing


def _adapt(root, *, question="Which repository adapter source is relevant?", context=None):
    return _adapter()(
        target_context=copy.deepcopy(context or CONTEXT),
        target_repository_root=root,
        question=question,
        now=NOW,
    )["receipt"]


def test_capture_wrapper_contains_cited_admitted_source_bytes(tmp_path):
    text = "export const adapter = 'bounded source';\n"
    (tmp_path / "adapter.ts").write_text(text)
    captured = _adapter()(
        target_context=copy.deepcopy(CONTEXT),
        target_repository_root=tmp_path,
        question="Which adapter source is relevant?",
        now=NOW,
    )
    assert set(captured) == {"receipt", "passages", "failures"}
    assert captured["failures"] == []
    receipt = captured["receipt"]
    assert "SEMANTIC_RELEVANCE_UNINTERPRETED" in receipt["unknowns"]
    assert len(captured["passages"]) == 1
    passage = captured["passages"][0]
    assert passage["source_path"] == "adapter.ts"
    assert passage["source_sha256"] == hashlib.sha256(text.encode()).hexdigest()
    artifact = passage["artifact"]
    assert artifact["role"] == "target"
    assert artifact["source_sha256"] == passage["source_sha256"]
    assert artifact["representation"]["text"] == text
    assert artifact["representation"]["sha256"] == passage["source_sha256"]
    citation = artifact["citations"][0]
    assert citation["artifact_id"] == artifact["id"]
    assert citation["representation_sha256"] == artifact["representation"]["sha256"]
    encoded = artifact["representation"]["text"].encode("utf-8")
    assert encoded[citation["start_byte"]:citation["end_byte"]].decode("utf-8") == citation["quote"]
    assert receipt["source_binding"]["head_oid"] in artifact["pin"]
    assert receipt["source_binding"]["inventory_sha256"] in artifact["pin"]


@pytest.mark.parametrize("text", [
    "GITHUB_TOKEN = 'synthetic-placeholder'\n",
    "github_token=synthetic-placeholder\n",
    'headers = {"Authorization": "Bearer synthetic-placeholder"}\n',
    "Authorization: Bearer synthetic-placeholder\n",
    "url = 'postgresql://synthetic-user:synthetic-placeholder@db.invalid/example'\n",
    "url = 'mysql://synthetic-user:synthetic-placeholder@db.invalid/example'\n",
    "url = 'mongodb+srv://synthetic-user:synthetic-placeholder@db.invalid/example'\n",
    "AWS_ACCESS_KEY_ID = 'synthetic-placeholder'\n",
    'config = {"aws_secret_access_key": "synthetic-placeholder"}\n',
    "AWS_ACCESS_KEY=synthetic-placeholder\n",
    # Base64url JSON header, empty JSON payload, and the word "synthetic";
    # deliberately no algorithm, identity claims, or authentic signature.
    "value = '" + base64.urlsafe_b64encode(
        b'{"synthetic":"rergsyntheticjwtmarker"}'
    ).decode().rstrip("=") + ".e30.c3ludGhldGlj'\n",
    'headers["Authorization"] = "Bearer rergsyntheticbearermarker"\n',
    "AWS_SESSION_TOKEN = 'rerg-placeholder-session-marker'\n",
    'config = {"aws_session_token": "rerg-placeholder-session-marker"}\n',
    "aws_session_token=rerg-placeholder-session-marker\n",
])
def test_capture_rejects_credential_bearing_source(tmp_path, text):
    (tmp_path / "adapter.py").write_text(text)
    captured = _adapter()(
        target_context=copy.deepcopy(CONTEXT),
        target_repository_root=tmp_path,
        question="Which adapter source is relevant?",
        now=NOW,
    )
    assert captured["passages"] == []
    assert captured["failures"] == [{
        "code": "UNSAFE_SOURCE_PASSAGE",
        "artifact_id": "target:adapter.py",
        "missing_fact": "A safe source excerpt is unavailable.",
        "decision_blocked": "Use of this source as implementation evidence.",
    }]
    assert text not in repr(captured)


@pytest.mark.parametrize("nearby", [
    'headers["Authorization"] = bearer_from_environment()\n',
    'headers["Authorization"] = "Bearer "\n',
    'headers["X-Authorization-Help"] = "Bearer documentation"\n',
    "AWS_SESSION_TOKEN = os.environ.get('AWS_SESSION_TOKEN')\n",
    "AWS_SESSION_TOKEN_HELP = 'documentation'\n",
    "value = 'package.module.attribute'\n",
])
def test_capture_safe_source_retains_host_review_ceiling(tmp_path, nearby):
    text = (
        "import os\n"
        "github_token = os.environ.get('GITHUB_TOKEN')\n"
        "url = 'postgresql://db.invalid/example'\n"
        "version = 'package.module.attribute'\n" + nearby
    )
    (tmp_path / "adapter.py").write_text(text)
    captured = _adapter()(
        target_context=copy.deepcopy(CONTEXT),
        target_repository_root=tmp_path,
        question="Which adapter source is relevant?",
        now=NOW,
    )
    assert captured["failures"] == []
    representation = captured["passages"][0]["artifact"]["representation"]
    assert representation["text"] == text
    assert representation["sanitization"] == {
        "method": "bounded-source-screen; host review required",
        "redacted": False,
    }


def test_unsafe_source_removes_all_parser_metadata_from_complete_result(tmp_path):
    marker = "rergsyntheticmetadatamarker"
    text = f"import {marker}\ndef {marker}():\n    password = '{marker}'\n"
    (tmp_path / "repository_adapter.py").write_text(text)
    result = _adapter()(
        target_context=copy.deepcopy(CONTEXT),
        target_repository_root=tmp_path,
        question="Which repository adapter source is relevant?",
        now=NOW,
    )
    assert marker not in repr(result)
    assert result["passages"] == []
    source = result["receipt"]["sources"][0]
    assert source["sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert source["relative_posix_path"] == "repository_adapter.py"
    assert source["language"] == "python"
    assert source["status"] == "PARSED"
    assert source["symbols"] == source["imports"] == source["literal_tokens"] == []
    assert source["parse_unknowns"] == []
    assert [failure["code"] for failure in result["failures"]] == ["UNSAFE_SOURCE_PASSAGE"]
    _validate_followup(result["receipt"])


@pytest.mark.parametrize("status", [
    "PARSED", "SYNTAX_ERROR", "PARSER_RESOURCE_LIMIT",
    "PARSER_UNAVAILABLE:python",
])
def test_unsafe_disclosure_preserves_terminal_parser_status(tmp_path, monkeypatch, status):
    module = importlib.import_module("rerg.repository_target_adapter")
    marker = "rergsyntheticunknownmarker"
    monkeypatch.setattr(module, "parse_source_facts", lambda *_: {
        "language": "python", "status": status,
        "symbols": [marker], "imports": [marker], "literal_tokens": [marker],
        "unknowns": [f"BARE_IMPORT:{marker}"],
    })
    (tmp_path / "repository_adapter.py").write_text(f"password = '{marker}'\n")
    result = _adapter()(
        target_context=copy.deepcopy(CONTEXT), target_repository_root=tmp_path,
        question="Which repository adapter source is relevant?", now=NOW,
    )
    source = result["receipt"]["sources"][0]
    assert source["language"] == "python"
    assert source["status"] == status
    assert source["symbols"] == source["imports"] == source["literal_tokens"] == []
    assert source["parse_unknowns"] == ([] if status == "PARSED" else [status])
    assert marker not in repr(result)
    assert result["passages"] == []
    assert [failure["code"] for failure in result["failures"]] == ["UNSAFE_SOURCE_PASSAGE"]
    _validate_followup(result["receipt"])


def test_resource_limit_receipt_validates_without_authorizing(tmp_path, monkeypatch):
    parser = importlib.import_module("rerg.source_parser")

    def fail(*_args, **_kwargs):
        raise MemoryError("synthetic resource failure")

    (tmp_path / "repository_adapter.py").write_text("def inspect_repository(): pass\n")
    with monkeypatch.context() as patch:
        patch.setattr(parser.ast, "parse", fail)
        receipt = _adapt(tmp_path)
    source = receipt["sources"][0]
    assert source["status"] == "PARSER_RESOURCE_LIMIT"
    assert source["parse_unknowns"] == ["PARSER_RESOURCE_LIMIT"]
    assert source["symbols"] == source["imports"] == source["literal_tokens"] == []
    _validate_followup(receipt)
    assert receipt["candidates"]
    assert all(candidate["authorizing"] is False for candidate in receipt["candidates"])


def test_disclosure_failure_is_rejected_as_parser_status(tmp_path):
    from rerg.path_query import MapBindingError
    (tmp_path / "repository_adapter.py").write_text("value = 1\n")
    receipt = _adapt(tmp_path)
    source = receipt["sources"][0]
    source.update(status="UNSAFE_SOURCE_PASSAGE", parse_unknowns=["UNSAFE_SOURCE_PASSAGE"],
                  symbols=[], imports=[], literal_tokens=[])
    with pytest.raises(MapBindingError) as caught:
        _validate_followup(receipt)
    assert caught.value.reasons == ("MAP_BINDING",)


@pytest.mark.parametrize("reason", [
    "SOURCE_ENCODING", "EMPTY_SOURCE_PASSAGE", "UNSAFE_SOURCE_PASSAGE",
    "FOLLOWUP_SOURCE_ENCODING", "FOLLOWUP_EMPTY_SOURCE_PASSAGE",
    "FOLLOWUP_UNSAFE_SOURCE_PASSAGE",
])
def test_parser_unknowns_reject_disclosure_namespace(tmp_path, reason):
    from rerg.path_query import MapBindingError
    (tmp_path / "repository_adapter.py").write_text("value = 1\n")
    receipt = _adapt(tmp_path)
    _validate_followup(receipt)
    receipt["sources"][0]["parse_unknowns"] = [reason]
    receipt["dependencies"]["unknowns"].append({
        "reason": reason, "path": "repository_adapter.py", "need_ids": ["need-inspect"],
    })
    receipt["unknowns"].append(reason)
    receipt["limitations"] = list(receipt["unknowns"])
    with pytest.raises(MapBindingError) as caught:
        _validate_followup(receipt)
    assert caught.value.reasons == ("MAP_BINDING",)


def _dependency_closure_case(tmp_path, monkeypatch, *, count=1, read_failure=None):
    module = importlib.import_module("rerg.repository_target_adapter")
    (tmp_path / "repository_adapter.ts").write_text("export const value = true;\n")
    for index in range(count):
        (tmp_path / f"dep{index}.ts").write_text("export const dep = true;\n")
    monkeypatch.setattr(module, "_source_facts", lambda *_: {
        "language": "typescript", "status": "PARSED", "symbols": [], "literal_tokens": [],
        "imports": [f"./dep{index}" for index in range(count)],
        "unknowns": ["DYNAMIC_IMPORT"],
    })
    if read_failure:
        original = module._read_regular_source

        def read(root, relative, budget):
            if relative.startswith("dep"):
                raise ValueError(read_failure)
            return original(root, relative, budget)

        monkeypatch.setattr(module, "_read_regular_source", read)
    return _adapt(tmp_path)


@pytest.mark.parametrize("excuse", [None, "wrong_path", "wrong_module", "wrong_reason", "file_limit"])
def test_dependency_closure_rejects_omitted_source_and_edge(tmp_path, monkeypatch, excuse):
    from rerg.path_query import MapBindingError
    receipt = _dependency_closure_case(tmp_path, monkeypatch)
    _validate_followup(receipt)
    assert receipt["sources"][0]["parse_unknowns"] == ["DYNAMIC_IMPORT"]
    assert len(receipt["dependencies"]["inferred"]) == 1
    receipt["dependencies"]["observed"] = [
        item for item in receipt["dependencies"]["observed"]
        if not (item["kind"] == "source" and item["path"] == "dep0.ts")
    ]
    receipt["dependencies"]["inferred"] = []
    if excuse:
        unknown = {
            "reason": "SOURCE_CHANGED", "path": "repository_adapter.ts",
            "module": "./dep0", "need_ids": ["need-inspect"],
        }
        if excuse == "wrong_path":
            unknown["path"] = "dep0.ts"
        elif excuse == "wrong_module":
            unknown["module"] = "./other"
        elif excuse == "wrong_reason":
            unknown["reason"] = "DYNAMIC_IMPORT"
        elif excuse == "file_limit":
            unknown["reason"] = "FILE_LIMIT"
        receipt["dependencies"]["unknowns"].append(unknown)
        if unknown["reason"] not in receipt["unknowns"]:
            receipt["unknowns"].append(unknown["reason"])
        receipt["limitations"] = list(receipt["unknowns"])
    with pytest.raises(MapBindingError) as caught:
        _validate_followup(receipt)
    assert caught.value.reasons == ("MAP_BINDING",)


@pytest.mark.parametrize("failure,reason", [
    ("INITIAL_READ_BYTE_LIMIT", "BYTE_LIMIT"),
    ("SOURCE_CHANGED", "SOURCE_CHANGED"),
    ("SENSITIVE_SURFACE_EXCLUDED", "EXCLUDED_DEPENDENCY"),
    ("SOURCE_CLEANUP_FAILED", "SOURCE_CLEANUP_FAILED"),
])
def test_dependency_closure_preserves_exact_read_failure(tmp_path, monkeypatch, failure, reason):
    from rerg.path_query import MapBindingError
    receipt = _dependency_closure_case(tmp_path, monkeypatch, read_failure=failure)
    expected = {
        "reason": reason, "path": "repository_adapter.ts",
        "module": "./dep0", "need_ids": ["need-inspect"],
    }
    assert expected in receipt["dependencies"]["unknowns"]
    assert receipt["dependencies"]["inferred"] == []
    _validate_followup(receipt)
    receipt["dependencies"]["unknowns"].remove(expected)
    with pytest.raises(MapBindingError) as caught:
        _validate_followup(receipt)
    assert caught.value.reasons == ("MAP_BINDING",)


def test_dependency_closure_preserves_file_limit(tmp_path, monkeypatch):
    from rerg.path_query import MapBindingError
    receipt = _dependency_closure_case(tmp_path, monkeypatch, count=9)
    expected = {
        "reason": "FILE_LIMIT", "path": "repository_adapter.ts",
        "module": "./dep8", "need_ids": ["need-inspect"],
    }
    assert len(receipt["dependencies"]["inferred"]) == 8
    assert expected in receipt["dependencies"]["unknowns"]
    _validate_followup(receipt)
    receipt["dependencies"]["unknowns"].remove(expected)
    with pytest.raises(MapBindingError) as caught:
        _validate_followup(receipt)
    assert caught.value.reasons == ("MAP_BINDING",)


def _write_bounded_frontier_tree(root, *, reverse=False):
    entries = [
        ("aaa_noise/candidate_locator.txt", "model todo handoff\n"),
        *[
            (f"aaa_noise/noise_{index:03}.txt", "irrelevant\n")
            for index in range(520)
        ],
        ("model/model_registry.ts", "export const model = true;\n"),
        ("todo/todo_store.ts", "export const todo = true;\n"),
        ("handoff/handoff_state.ts", "export const handoff = true;\n"),
    ]
    for relative, content in reversed(entries) if reverse else entries:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def _adapt_bounded_frontier(root):
    return _adapt(
        root,
        question="Where are the model todo and handoff surfaces?",
        context={
            "target": "gajae-code",
            "load_bearing_needs": [{
                "need_id": "need-runtime-surfaces",
                "statement": "inspect model todo handoff runtime surfaces",
            }],
        },
    )


def test_git_inventory_prevents_oversized_directory_starvation_and_selects_concepts(
    tmp_path,
):
    _write_bounded_frontier_tree(tmp_path)
    _initialize_git_fixture(tmp_path)

    receipt = _adapt_bounded_frontier(tmp_path)

    selected = receipt["path_ranking"]["phase1_candidates"]
    selected_paths = [item["relative_posix_path"] for item in selected]
    assert "model/model_registry.ts" in selected_paths
    assert "todo/todo_store.ts" in selected_paths
    assert "handoff/handoff_state.ts" in selected_paths
    assert receipt["source_binding"]["head_oid"]
    assert receipt["source_binding"]["inventory_sha256"]
    assert receipt["evidence_class"] == "implementation_source"
    assert "IGNORE_RULES_UNPARSED" not in receipt["unknowns"]


def test_greedy_selector_maximizes_new_concepts_before_score(tmp_path):
    for relative in (
        "model/model_model_model.py",
        "model/todo.py",
        "handoff.py",
        "todo.py",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("VALUE = 1\n")
    _initialize_git_fixture(tmp_path)

    receipt = _adapt(
        tmp_path,
        question="model todo handoff",
        context={
            "target": "gajae-code",
            "load_bearing_needs": [{
                "need_id": "need-runtime",
                "statement": "model todo handoff",
            }],
        },
    )

    selected = receipt["path_ranking"]["phase1_candidates"]
    assert selected[0]["relative_posix_path"] == "model/todo.py"
    assert selected[0]["marginal_at_selection"] == 2
    assert selected[1]["relative_posix_path"] == "handoff.py"
    assert selected[1]["marginal_at_selection"] == 1
    assert [item["rank"] for item in selected] == list(
        range(1, len(selected) + 1)
    )


def test_producer_and_validator_path_selection_are_mechanically_equivalent():
    producer = importlib.import_module("rerg.repository_target_adapter")
    validator = importlib.import_module("rerg.path_query")
    cases = [
        (
            [
                "model/model_model_model.py",
                "model/todo.py",
                "handoff.py",
                "todo.py",
                "docs/model.md",
            ],
            ["model", "todo", "handoff"],
        ),
        (
            [
                "packages/agent/src/session_courier.ts",
                "packages/agent/src/session_kickoff.tsx",
                "packages/agent/src/task_runner.py",
                "packages/agent/README.md",
                "tools/session-courier.mjs",
            ],
            ["session", "courier", "task", "agent"],
        ),
        (
            [
                "z/repository_adapter.py",
                "a/repository_adapter.py",
                "repository_adapter_test.txt",
                "safe/source.py",
                "source/safe.ts",
                "source/safe.txt",
                "other/noise.py",
                "adapter/repository.py",
                "adapter/repository.tsx",
            ],
            ["repository", "adapter", "safe", "source"],
        ),
    ]

    for paths, tokens in cases:
        assert producer._rank_paths(paths, tokens) == validator._select_rankings(
            paths, tokens
        )


def test_selection_excludes_locator_tokens_with_competing_filenames(tmp_path):
    roots = [tmp_path / "a", tmp_path / "b"]
    for index, root in enumerate(roots):
        root.mkdir()
        (root / "todo.py").write_text(f"BODY = {index}\n")
        (root / "handoff.py").write_text(f"OTHER = {index}\n")
        (root / "one.py").write_text("LOCATOR = 1\n")
        (root / "different.py").write_text("LOCATOR = 2\n")
        _initialize_git_fixture(root)

    receipts = [
        _adapt(
            root,
            question=locator + " todo handoff",
            context={
                "target": "gajae-code",
                "load_bearing_needs": [{
                    "need_id": "need-runtime",
                    "statement": "todo handoff",
                }],
            },
        )
        for root, locator in zip(
            roots,
            ("https://candidate.invalid/one", "repository://different"),
        )
    ]

    projection = lambda receipt: [
        (
            item["relative_posix_path"],
            item["path_score"],
            item["matched_concepts"],
            item["marginal_at_selection"],
        )
        for item in receipt["path_ranking"]["phase1_candidates"]
    ]
    assert projection(receipts[0]) == projection(receipts[1])
    assert {
        item["relative_posix_path"]
        for item in receipts[0]["path_ranking"]["phase1_candidates"]
    } == {"handoff.py", "todo.py"}


def _initialize_git_fixture(root):
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "--", "."], cwd=root, check=True)
    commit_environment = {
        **os.environ,
        "GIT_AUTHOR_DATE": "2026-09-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2026-09-01T00:00:00Z",
    }
    subprocess.run(
        [
            "git", "-c", "user.name=RERG Test",
            "-c", "user.email=rerg@example.invalid",
            "commit", "-qm", "fixture",
        ],
        cwd=root,
        check=True,
        env=commit_environment,
    )


def test_external_candidate_is_not_a_target_seed_and_missing_root_abstains(tmp_path):
    source = tmp_path / "repository_adapter.py"
    source.write_text("def inspect_repository():\n    return 'source'\n")
    receipt = _adapt(tmp_path, question="https://stencil.invalid/provider repository adapter")
    assert [item["relative_posix_path"] for item in receipt["sources"]] == [
        "repository_adapter.py"
    ]
    assert all("stencil" not in item["relative_posix_path"] for item in receipt["sources"])
    assert "NO_LOCAL_SOURCE_ROOT" not in receipt["unknowns"]

    absent = _adapt(tmp_path / "missing")
    assert absent["sources"] == []
    assert absent["candidates"] == []
    assert absent["unknowns"] == ["NO_LOCAL_SOURCE_ROOT"]

    linked_root = tmp_path.parent / f"linked-{tmp_path.name}"
    linked_root.symlink_to(tmp_path, target_is_directory=True)
    unsafe = _adapt(linked_root)
    assert unsafe["unknowns"] == ["NO_LOCAL_SOURCE_ROOT"]


def test_sorted_git_inventory_exclusions_and_ignore_policy(tmp_path):
    for relative, content in {
        "z/repository_adapter.py": "Z = 1\n",
        "a/repository_adapter.py": "A = 1\n",
        ".gjc/runtime/state.py": "SECRET = 1\n",
        "dist/repository_adapter.py": "DIST = 1\n",
        ".env.local": "TOKEN=x",
        "private.key": "KEY",
        ".gitignore": "vendor/\n",
    }.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    receipt = _adapt(tmp_path)
    phase1 = receipt["path_ranking"]["phase1_candidates"]
    assert [item["relative_posix_path"] for item in phase1] == [
        "a/repository_adapter.py", "z/repository_adapter.py"
    ]
    assert receipt["exclusions"] == [
        {"category": "sensitive", "relative_posix_path": ".env.local"},
        {"category": "ignore_rules", "relative_posix_path": ".gitignore"},
        {"category": "runtime", "relative_posix_path": ".gjc"},
        {"category": "generated", "relative_posix_path": "dist"},
        {"category": "sensitive", "relative_posix_path": "private.key"},
    ]
    assert receipt["inventory"]["ignore_policy"] == "git-exclude-standard"
    assert "IGNORE_RULES_UNPARSED" not in receipt["unknowns"]
    assert "SENSITIVE_SURFACE_EXCLUDED" in receipt["unknowns"]


def test_git_metadata_directory_is_not_inventory_without_corrupting_git_config(tmp_path):
    (tmp_path / ".git" / "not_inventory.py").write_text("SECRET = 1\n")
    (tmp_path / "repository_adapter.py").write_text("VALUE = 1\n")

    receipt = _adapt(tmp_path)

    assert ".git/not_inventory.py" not in {
        item["path"] for item in receipt["inventory"]["records"]
    }
    assert [item["relative_posix_path"] for item in receipt["sources"]] == [
        "repository_adapter.py"
    ]


def test_post_git_source_read_closes_each_descriptor(tmp_path, monkeypatch):
    child = tmp_path / "child"
    child.mkdir()
    (child / "source.py").write_text("VALUE = 1\n")
    module = importlib.import_module("rerg.repository_target_adapter")
    original_open = module.os.open
    original_close = module.os.close
    opened_descriptors = []
    closed_descriptors = []

    def spying_open(path, *args, **kwargs):
        descriptor = original_open(path, *args, **kwargs)
        opened_descriptors.append(descriptor)
        return descriptor

    def spying_close(descriptor):
        closed_descriptors.append(descriptor)
        return original_close(descriptor)

    monkeypatch.setattr(module.os, "open", spying_open)
    monkeypatch.setattr(module.os, "close", spying_close)
    result = module._read_regular_source(
        tmp_path, "child/source.py", 1024
    )
    assert result["data"] == b"VALUE = 1\n"
    assert sorted(closed_descriptors) == sorted(opened_descriptors)


def test_root_directory_replacement_after_inventory_fails_before_receipting_bytes(
    tmp_path, monkeypatch,
):
    target = tmp_path / "target"
    target.mkdir()
    (target / "repository_adapter.py").write_text("def safe_repository_adapter(): pass\n")
    _initialize_git_fixture(target)
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "repository_adapter.py").write_text("def unsafe_repository_adapter(): pass\n")
    displaced = tmp_path / "displaced"
    module = importlib.import_module("rerg.repository_target_adapter")
    original_inventory = module.collect_git_worktree_inventory

    def replacing_inventory(root):
        receipt = original_inventory(root)
        target.rename(displaced)
        replacement.rename(target)
        return receipt

    monkeypatch.setattr(module, "collect_git_worktree_inventory", replacing_inventory)

    receipt = _adapt(target)

    assert receipt["sources"] == []
    assert receipt["candidates"] == []
    assert receipt["unknowns"] == ["SOURCE_CHANGED"]


def test_root_symlink_swap_after_inventory_fails_before_reading_outside(
    tmp_path, monkeypatch,
):
    target = tmp_path / "target"
    target.mkdir()
    (target / "repository_adapter.py").write_text("def safe_repository_adapter(): pass\n")
    _initialize_git_fixture(target)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "repository_adapter.py").write_text("def unsafe_repository_adapter(): pass\n")
    displaced = tmp_path / "displaced"
    module = importlib.import_module("rerg.repository_target_adapter")
    original_inventory = module.collect_git_worktree_inventory
    original_read = module.os.read

    def replacing_inventory(root):
        receipt = original_inventory(root)
        target.rename(displaced)
        target.symlink_to(outside, target_is_directory=True)
        return receipt

    def forbidden_outside_read(fd, size):
        descriptor_target = os.readlink(f"/proc/self/fd/{fd}")
        if descriptor_target.startswith(str(outside)):
            raise AssertionError("outside replacement body was read")
        return original_read(fd, size)

    monkeypatch.setattr(module, "collect_git_worktree_inventory", replacing_inventory)
    monkeypatch.setattr(module.os, "read", forbidden_outside_read)

    receipt = _adapt(target)

    assert receipt["sources"] == []
    assert receipt["unknowns"] == ["SOURCE_CHANGED"]


def test_final_file_fifo_replacement_uses_nonblocking_open_and_fstat_mode_gate(
    tmp_path, monkeypatch,
):
    (tmp_path / "repository_adapter.py").write_text("def repository_adapter(): pass\n")
    module = importlib.import_module("rerg.repository_target_adapter")
    original_open = module.os.open
    replaced = False

    def fifo_race_open(path, flags, *args, **kwargs):
        nonlocal replaced
        if path == "repository_adapter.py" and not replaced:
            replaced = True
            (tmp_path / "repository_adapter.py").unlink()
            os.mkfifo(tmp_path / "repository_adapter.py")
            assert flags & module.os.O_NONBLOCK
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", fifo_race_open)

    receipt = _adapt(tmp_path)

    assert receipt["sources"] == []
    assert "NOT_REGULAR_FILE" in receipt["unknowns"]
    assert "repository_adapter.py" in receipt["uninspected_surfaces"]


def test_post_git_read_rejects_inward_and_outward_untracked_symlinks(tmp_path):
    inside = tmp_path / "inside.py"
    inside.write_text("def repository_adapter(): pass\n")
    outside = tmp_path.parent / f"outside-{tmp_path.name}.py"
    outside.write_text("def repository_adapter(): pass\n")
    (tmp_path / "repository_inward.py").symlink_to(inside)
    (tmp_path / "repository_outward.py").symlink_to(outside)

    receipt = _adapt(tmp_path)

    assert {
        "repository_inward.py", "repository_outward.py",
    } <= set(receipt["uninspected_surfaces"])
    assert {
        item["relative_posix_path"] for item in receipt["sources"]
    }.isdisjoint({"repository_inward.py", "repository_outward.py"})
    assert "SOURCE_ESCAPE" in receipt["unknowns"]


def test_post_git_source_read_closes_descriptors_on_injected_read_failure(
    tmp_path, monkeypatch,
):
    child = tmp_path / "child"
    child.mkdir()
    (child / "source.py").write_text("VALUE = 1\n")
    module = importlib.import_module("rerg.repository_target_adapter")
    original_open = module.os.open
    original_close = module.os.close
    opened = []
    closed = []

    def spying_open(path, *args, **kwargs):
        descriptor = original_open(path, *args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def spying_close(descriptor):
        closed.append(descriptor)
        return original_close(descriptor)

    monkeypatch.setattr(module.os, "open", spying_open)
    monkeypatch.setattr(module.os, "close", spying_close)
    monkeypatch.setattr(
        module.os, "read",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("injected")),
    )
    with pytest.raises(OSError, match="injected"):
        module._read_regular_source(tmp_path, "child/source.py", 1024)
    assert sorted(closed) == sorted(opened)


def test_descriptor_cleanup_attempts_all_component_closes_after_first_failure(
    tmp_path, monkeypatch,
):
    child = tmp_path / "child"
    child.mkdir()
    (child / "source.py").write_text("VALUE = 1\n")
    module = importlib.import_module("rerg.repository_target_adapter")
    original_open = module.os.open
    original_close = module.os.close
    opened = []
    attempted = []

    def spying_open(path, *args, **kwargs):
        descriptor = original_open(path, *args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def failing_first_close(descriptor):
        attempted.append(descriptor)
        if len(attempted) == 1:
            raise OSError("first close failed")
        return original_close(descriptor)

    monkeypatch.setattr(module.os, "open", spying_open)
    monkeypatch.setattr(module.os, "close", failing_first_close)

    with pytest.raises(ValueError, match="SOURCE_CLEANUP_FAILED"):
        module._stat_regular_source(tmp_path, "child/source.py")

    assert sorted(attempted) == sorted(opened)


def test_final_descriptor_cleanup_failure_prevents_successful_body_receipt(
    tmp_path, monkeypatch,
):
    child = tmp_path / "child"
    child.mkdir()
    (child / "source.py").write_text("VALUE = 1\n")
    module = importlib.import_module("rerg.repository_target_adapter")
    original_open = module.os.open
    original_close = module.os.close
    final_fd = None
    attempted = []

    def track_final_open(path, *args, **kwargs):
        nonlocal final_fd
        descriptor = original_open(path, *args, **kwargs)
        if path == "source.py":
            final_fd = descriptor
        return descriptor

    def fail_final_close(descriptor):
        attempted.append(descriptor)
        if descriptor == final_fd:
            raise OSError("final close failed")
        return original_close(descriptor)

    monkeypatch.setattr(module.os, "open", track_final_open)
    monkeypatch.setattr(module.os, "close", fail_final_close)

    with pytest.raises(ValueError, match="SOURCE_CLEANUP_FAILED"):
        module._read_regular_source(tmp_path, "child/source.py", 1024)

    assert final_fd in attempted


def test_bound_root_close_failure_converts_successful_adaptation_to_cleanup_failure(
    tmp_path, monkeypatch,
):
    (tmp_path / "repository_adapter.py").write_text("def repository_adapter(): pass\n")
    module = importlib.import_module("rerg.repository_target_adapter")
    original_close = module.os.close
    root_fd = None

    original_open_bound_root = module._open_bound_root

    def tracked_open_bound_root(path):
        nonlocal root_fd
        root = original_open_bound_root(path)
        root_fd = root.fd
        return root

    def fail_root_close(descriptor):
        if descriptor == root_fd:
            raise OSError("root close failed")
        return original_close(descriptor)

    monkeypatch.setattr(module, "_open_bound_root", tracked_open_bound_root)
    monkeypatch.setattr(module.os, "close", fail_root_close)

    receipt = _adapt(tmp_path)

    assert receipt["sources"] == []
    assert receipt["unknowns"] == ["SOURCE_CLEANUP_FAILED"]


@pytest.mark.parametrize(
    "relative",
    ["id_rsa", "private-key.py", "certificate"],
)
def test_sensitive_component_policy_excludes_extensionless_and_hyphenated_names(
    tmp_path, relative,
):
    (tmp_path / relative).write_text("repository adapter source\n")
    receipt = _adapt(tmp_path)
    assert receipt["sources"] == []
    assert receipt["exclusions"] == [{
        "category": "sensitive",
        "relative_posix_path": relative,
    }]
    assert "SENSITIVE_SURFACE_EXCLUDED" in receipt["unknowns"]


@pytest.mark.parametrize(
    ("dependency", "import_statement", "category", "excluded_surface"),
    [
        ("private_key.ts", "import './private_key';", "sensitive", "private_key.ts"),
        ("generated.ts", "import './generated';", "generated", "generated.ts"),
        ("venv/index.ts", "import './venv';", "runtime", "venv"),
    ],
)
def test_excluded_dependencies_are_never_opened_or_receipted(
    tmp_path, monkeypatch, dependency, import_statement, category,
    excluded_surface,
):
    source = tmp_path / "repository_adapter.py"
    source = tmp_path / "repository_adapter.ts"
    source.write_text(f"{import_statement}\n")
    excluded = tmp_path / dependency
    excluded.parent.mkdir(parents=True, exist_ok=True)
    excluded.write_text("raise AssertionError('excluded body was opened')\n")
    module = importlib.import_module("rerg.repository_target_adapter")
    original = module.os.open

    def guarded_open(path, *args, **kwargs):
        if path in {excluded.name, str(excluded)}:
            raise AssertionError("excluded dependency body was opened")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", guarded_open)
    receipt = _adapt(tmp_path)
    assert {
        "category": category,
        "relative_posix_path": excluded_surface,
    } in receipt["exclusions"]
    assert all(
        item.get("path") != dependency
        for item in receipt["dependencies"]["observed"]
    )
    assert all(
        item.get("dependency_path") != dependency
        for item in receipt["dependencies"]["inferred"]
    )
    assert "EXCLUDED_DEPENDENCY" in receipt["unknowns"]


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux byte paths")
def test_non_utf8_path_fails_closed_before_receipt_identity(tmp_path):
    raw_name = b"repository_\xff_adapter.py"
    directory = os.fsencode(tmp_path)
    descriptor = os.open(
        directory + b"/" + raw_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        os.write(descriptor, b"def inspect_repository(): pass\n")
    finally:
        os.close(descriptor)

    receipt = _adapt(tmp_path)
    assert receipt["sources"] == []
    assert "GIT_INVENTORY_MALFORMED" in receipt["unknowns"]
    assert "\\udcff" not in repr(receipt)

    envelope = {
        "target_harness": {"target": "hermes-static"},
        "inferred_needs_constraints": [{
            "need_id": "need-inspect",
            "statement": "read the repository map",
            "load_bearing": True,
            "evidence_refs": ["ev-need"],
        }],
    }
    from rerg.path_query import _validate_adapter_receipt
    _validate_adapter_receipt(receipt, target=envelope["target_harness"]["target"], now=NOW,
    question="Which repository adapter source is relevant?",
    need_ids=[need["need_id"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
    statements=[need["statement"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],)

    assert receipt["candidates"] == []


def test_whole_git_inventory_is_not_prefix_truncated(tmp_path):
    for index in range(513):
        (tmp_path / f"adapter_{index:03}.py").write_text("VALUE = 1\n")
    receipt = _adapt(tmp_path)
    assert receipt["path_ranking"]["inventory_records"] == 513
    assert receipt["enumeration_truncated"] is False
    assert "ENUMERATION_TRUNCATED" not in receipt["unknowns"]
    assert len(receipt["uninspected_surfaces"]) == 505
    assert all(item["authorizing"] is False for item in receipt["candidates"])


def test_whole_git_inventory_records_every_untracked_path(tmp_path):
    for index in range(20):
        (tmp_path / f"entry_{index:02}.txt").write_text("irrelevant\n")
    receipt = _adapt(tmp_path)
    assert receipt["path_ranking"]["inventory_records"] == 20
    assert [item["path"] for item in receipt["inventory"]["records"]] == [
        f"entry_{index:02}.txt" for index in range(20)
    ]
    assert receipt["enumeration_truncated"] is False


def test_nonmatching_inventory_paths_are_not_opened_or_body_read(
    tmp_path, monkeypatch,
):
    oversized = tmp_path / "oversized"
    oversized.mkdir()
    (oversized / "prefix_child").mkdir()
    for index in range(20):
        (oversized / f"entry_{index:02}.py").write_text(
            "raise AssertionError('incomplete body opened')\n"
        )
    module = importlib.import_module("rerg.repository_target_adapter")

    def forbidden_read(*_args, **_kwargs):
        raise AssertionError("incomplete body opened")

    monkeypatch.setattr(module, "_read_regular_source", forbidden_read)
    receipt = _adapt(tmp_path)

    assert receipt["sources"] == []
    assert receipt["enumeration_truncated"] is False
    assert len(receipt["uninspected_surfaces"]) == 20
    assert all(
        item["relative_posix_path"] != "oversized/prefix_child"
        for item in receipt["exclusions"]
    )


def test_git_inventory_reaches_later_relevant_directories(tmp_path):
    _write_bounded_frontier_tree(tmp_path)
    receipt = _adapt_bounded_frontier(tmp_path)

    relevant = {
        "handoff/handoff_state.ts",
        "model/model_registry.ts",
        "todo/todo_store.ts",
    }
    assert relevant <= {
        item["relative_posix_path"]
        for item in receipt["path_ranking"]["phase1_candidates"]
    }
    assert relevant <= {
        item["relative_posix_path"] for item in receipt["sources"]
    }
    assert receipt["path_ranking"]["inventory_records"] == 524
    assert receipt["enumeration_truncated"] is False
    assert "UNSUPPORTED_LANGUAGE" not in receipt["unknowns"]
    assert all(
        item["language"] == "typescript"
        for item in receipt["sources"]
        if item["relative_posix_path"].endswith(".ts")
    )


def test_git_inventory_selection_is_creation_order_and_cwd_independent(
    tmp_path, monkeypatch,
):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    _write_bounded_frontier_tree(first_root)
    _write_bounded_frontier_tree(second_root, reverse=True)
    _initialize_git_fixture(first_root)
    _initialize_git_fixture(second_root)

    first = _adapt_bounded_frontier(first_root)
    monkeypatch.chdir(tmp_path.parent)
    second = _adapt_bounded_frontier(second_root)

    assert second == first


def test_unselected_candidate_body_cannot_influence_selection(tmp_path):
    _write_bounded_frontier_tree(tmp_path)
    _initialize_git_fixture(tmp_path)
    (tmp_path / "aaa_noise/candidate_locator.txt").write_text(
        "dirty tracked body with unchanged path state before selection\n"
    )
    first = _adapt_bounded_frontier(tmp_path)
    (tmp_path / "aaa_noise/candidate_locator.txt").write_text(
        "different dirty tracked body with unchanged path state after selection\n"
    )
    second = _adapt_bounded_frontier(tmp_path)

    assert second == first
    assert first["uninspected_surfaces"] == [
        "aaa_noise/candidate_locator.txt",
        *[f"aaa_noise/noise_{index:03}.txt" for index in range(520)],
    ]


def test_inventory_without_lexical_signal_selects_no_paths(tmp_path):
    for directory in ("aaa", "zzz"):
        for index in range(300):
            path = tmp_path / directory / f"item_{index:03}.txt"
            path.parent.mkdir(exist_ok=True)
            path.write_text("irrelevant\n")
    receipt = _adapt(tmp_path, question="which source is safe?")
    assert receipt["path_ranking"]["inventory_records"] == 600
    assert receipt["path_ranking"]["phase1_candidates"] == []
    assert len(receipt["uninspected_surfaces"]) == 600


def test_path_name_ranking_precedes_bounded_reads_and_is_stable(tmp_path):
    for index in range(12):
        name = f"repository_adapter_{index:02}.py"
        (tmp_path / name).write_text(f"def symbol_{index}():\n    return 'literal_{index}'\n")
    receipt = _adapt(tmp_path)
    assert len(receipt["path_ranking"]["normalized_tokens"]) <= 64
    assert len(receipt["path_ranking"]["phase1_candidates"]) == 8
    assert len(receipt["sources"]) == 8
    expected = [f"repository_adapter_{index:02}.py" for index in range(8)]
    assert [item["relative_posix_path"] for item in receipt["sources"]] == expected
    assert receipt["path_ranking"]["max_pre_stat_candidates"] == 8
    assert receipt["path_ranking"]["max_initial_read_bytes"] == 4 * 1024 * 1024
    assert receipt["uninspected_surfaces"] == [
        f"repository_adapter_{index:02}.py" for index in range(8, 12)
    ]
    assert all(len(item["symbols"]) <= 128 for item in receipt["sources"])
    assert all(len(item["literal_tokens"]) <= 64 for item in receipt["sources"])
    assert [item["relative_posix_path"] for item in receipt["candidates"]] == [
        item["relative_posix_path"] for item in receipt["sources"]
    ]
    assert [item["score"] for item in receipt["candidates"]] == [
        item["path_score"] for item in receipt["sources"]
    ]


def test_initial_read_budget_and_dependency_limits_are_visible(tmp_path):
    (tmp_path / "repository_adapter.py").write_bytes(b"#" + b"x" * (4 * 1024 * 1024))
    receipt = _adapt(tmp_path)
    assert receipt["sources"] == []
    assert "INITIAL_READ_BYTE_LIMIT" in receipt["unknowns"]
    assert "repository_adapter.py" in receipt["uninspected_surfaces"]

    (tmp_path / "repository_adapter.ts").write_text(
        "import './missing_local';\n"
        "const name = './dynamic_name';\n"
        "const loaded = import(name);\n"
    )
    receipt = _adapt(tmp_path)
    assert receipt["dependencies"]["limits"] == {
        "max_dependency_files": 8,
        "max_depth": 1,
        "max_file_bytes": 1_048_576,
        "max_total_bytes": 4_194_304,
    }
    reasons = {item["reason"] for item in receipt["dependencies"]["unknowns"]}
    assert {"UNRESOLVED_LOCAL_REFERENCE", "DYNAMIC_IMPORT"} <= reasons


def test_js_ts_local_dependency_resolution_exact_extensionless_and_index(tmp_path):
    (tmp_path / "repository_adapter.ts").write_text(
        "import './exact.ts';\n"
        "import './extensionless';\n"
        "import './folder';\n"
    )
    (tmp_path / "exact.ts").write_text("export const exact = true;\n")
    (tmp_path / "extensionless.tsx").write_text("export const extensionless = true;\n")
    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / "index.ts").write_text("export const index = true;\n")

    receipt = _adapt(tmp_path)

    inferred = {
        (item["source_path"], item["dependency_path"])
        for item in receipt["dependencies"]["inferred"]
    }
    assert inferred == {
        ("repository_adapter.ts", "exact.ts"),
        ("repository_adapter.ts", "extensionless.tsx"),
        ("repository_adapter.ts", "folder/index.ts"),
    }
    assert receipt["dependencies"]["limits"] == {
        "max_dependency_files": 8,
        "max_depth": 1,
        "max_file_bytes": 1_048_576,
        "max_total_bytes": 4_194_304,
    }


@pytest.mark.parametrize("suffix,language", [
    ("py", "python"), ("js", "javascript"), ("ts", "typescript"), ("tsx", "tsx"),
])
def test_invalid_js_ts_encoding_emits_no_fabricated_dependency(tmp_path, suffix, language):
    (tmp_path / f"repository_adapter.{suffix}").write_bytes(
        b"import './\xffdep';\nexport const value = 'visible';\n"
    )
    (tmp_path / "dep.ts").write_text("export const dep = true;\n")

    result = _adapter()(
        target_context=copy.deepcopy(CONTEXT), target_repository_root=tmp_path,
        question="Which repository adapter source is relevant?", now=NOW,
    )
    receipt = result["receipt"]
    assert result["passages"] == []
    assert [failure["code"] for failure in result["failures"]] == ["SOURCE_ENCODING"]
    _validate_followup(receipt)

    assert receipt["sources"][0]["language"] == language
    assert receipt["sources"][0]["status"] == "INVALID_SOURCE_ENCODING"
    assert receipt["sources"][0]["symbols"] == []
    assert receipt["sources"][0]["imports"] == []
    assert receipt["sources"][0]["literal_tokens"] == []
    assert "INVALID_SOURCE_ENCODING" in receipt["unknowns"]
    assert receipt["dependencies"]["inferred"] == []
    assert all(
        item.get("path") != "dep.ts"
        for item in receipt["dependencies"]["observed"]
    )


def test_local_dependency_resolution_ambiguity_and_escape_are_visible(tmp_path):
    (tmp_path / "repository_adapter.ts").write_text(
        "import './ambiguous';\n"
        "import '../escaped';\n"
        "import './missing';\n"
    )
    (tmp_path / "ambiguous.ts").write_text("export const ts = true;\n")
    (tmp_path / "ambiguous.tsx").write_text("export const tsx = true;\n")

    receipt = _adapt(tmp_path)

    assert receipt["dependencies"]["inferred"] == []
    unknowns = receipt["dependencies"]["unknowns"]
    assert {
        "reason": "AMBIGUOUS_LOCAL_REFERENCE",
        "path": "repository_adapter.ts",
        "module": "./ambiguous",
        "need_ids": ["need-inspect"],
    } in unknowns
    assert {
        "reason": "LOCAL_REFERENCE_ESCAPE",
        "path": "repository_adapter.ts",
        "module": "../escaped",
        "need_ids": ["need-inspect"],
    } in unknowns
    assert {
        "reason": "UNRESOLVED_LOCAL_REFERENCE",
        "path": "repository_adapter.ts",
        "module": "./missing",
        "need_ids": ["need-inspect"],
    } in unknowns


def test_local_dependency_one_hop_file_and_byte_bounds(tmp_path, monkeypatch):
    imports = "\n".join(f"import './dep_{index:02}';" for index in range(10))
    (tmp_path / "repository_adapter.ts").write_text(imports + "\n")
    for index in range(10):
        (tmp_path / f"dep_{index:02}.ts").write_text(
            "import './second_hop';\nexport const value = true;\n"
        )
    (tmp_path / "second_hop.ts").write_text("export const forbidden = true;\n")
    module = importlib.import_module("rerg.repository_target_adapter")
    original = module._read_regular_source
    opened = []

    def spying_read(root, relative, byte_budget):
        opened.append(relative)
        return original(root, relative, byte_budget)

    monkeypatch.setattr(module, "_read_regular_source", spying_read)
    receipt = _adapt(tmp_path)

    assert "second_hop.ts" not in opened
    dependency_paths = [
        item["dependency_path"] for item in receipt["dependencies"]["inferred"]
    ]
    assert dependency_paths == [f"dep_{index:02}.ts" for index in range(8)]
    assert {
        "reason": "FILE_LIMIT",
        "path": "repository_adapter.ts",
        "module": "./dep_08",
        "need_ids": ["need-inspect"],
    } in receipt["dependencies"]["unknowns"]

    (tmp_path / "repository_adapter.ts").write_text("import './oversized';\n")
    (tmp_path / "oversized.ts").write_bytes(b"x" * (1_048_576 + 1))
    receipt = _adapt(tmp_path)
    assert receipt["dependencies"]["inferred"] == []
    assert {
        "reason": "BYTE_LIMIT",
        "path": "repository_adapter.ts",
        "module": "./oversized",
        "need_ids": ["need-inspect"],
    } in receipt["dependencies"]["unknowns"]


def test_dependency_file_limit_bounds_body_reads_and_inferred_receipts(tmp_path):
    module_names = [f"local_dependency_{index:02}" for index in range(10)]
    (tmp_path / "repository_adapter.ts").write_text(
        "\n".join(f"import './{name}';" for name in module_names) + "\n"
    )
    for name in module_names:
        (tmp_path / f"{name}.ts").write_text("export const value = 1;\n")

    receipt = _adapt(tmp_path)
    dependency_receipt = receipt["dependencies"]
    source_records = [
        item for item in dependency_receipt["observed"]
        if item["kind"] == "source"
    ]
    assert len(source_records) == 9
    assert len(dependency_receipt["inferred"]) == 8
    assert any(
        item["reason"] == "FILE_LIMIT"
        for item in dependency_receipt["unknowns"]
    )


def test_dependency_second_hop_precedes_terminal_body_read(tmp_path, monkeypatch):
    (tmp_path / "repository_adapter.ts").write_text("import './depth_1';\n")
    (tmp_path / "depth_1.ts").write_text("import './depth_2';\n")
    (tmp_path / "depth_2.ts").write_text("export const terminal = true;\n")

    module = importlib.import_module("rerg.repository_target_adapter")
    original = module.os.open
    opened_terminal = False

    def spying_open(path, *args, **kwargs):
        nonlocal opened_terminal
        if path in {"depth_2.ts", str(tmp_path / "depth_2.ts")}:
            opened_terminal = True
        return original(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", spying_open)
    receipt = _adapt(tmp_path)

    assert opened_terminal is False
    assert all(
        item.get("path") != "depth_2.ts"
        for item in receipt["dependencies"]["observed"]
    )
    assert all(
        item["source_path"] != "depth_1.ts"
        and item["dependency_path"] != "depth_2.ts"
        for item in receipt["dependencies"]["inferred"]
    )


def test_symlink_escape_and_source_change_never_receipt_bytes(tmp_path, monkeypatch):
    outside = tmp_path.parent / f"outside-{tmp_path.name}.py"
    outside.write_text("def repository_adapter(): pass\n")
    (tmp_path / "repository_adapter.py").symlink_to(outside)
    escaped = _adapt(tmp_path)
    assert escaped["sources"] == []
    assert "SOURCE_ESCAPE" in escaped["unknowns"]
    assert "repository_adapter.py" in escaped["uninspected_surfaces"]

    (tmp_path / "repository_adapter.py").unlink()
    source = tmp_path / "repository_adapter.py"
    source.write_text("def repository_adapter(): pass\n")
    module = importlib.import_module("rerg.repository_target_adapter")
    original = module._read_regular_source

    def changing(*args, **kwargs):
        result = original(*args, **kwargs)
        source.write_text("def changed(): pass\n")
        return result

    monkeypatch.setattr(module, "_read_regular_source", changing)
    changed = _adapt(tmp_path)
    assert changed["sources"] == []
    assert changed["candidates"] == []
    assert "SOURCE_CHANGED" in changed["unknowns"]
    assert "repository_adapter.py" in changed["uninspected_surfaces"]


def test_public_candidates_preserve_lexical_selection_order_not_body_fact_order(
    tmp_path,
):
    (tmp_path / "model_todo.py").write_text("VALUE = 1\n")
    (tmp_path / "handoff.py").write_text(
        "\n".join(f"def body_symbol_{index}(): pass" for index in range(20))
    )
    receipt = _adapt(
        tmp_path,
        question="model todo handoff",
        context={
            "target": "hermes-static",
            "load_bearing_needs": [{
                "need_id": "need-inspect",
                "statement": "model todo handoff",
            }],
        },
    )
    assert [
        item["relative_posix_path"] for item in receipt["candidates"]
    ] == [
        item["relative_posix_path"] for item in receipt["sources"]
    ]
    assert [
        item["score"] for item in receipt["candidates"]
    ] == [
        item["path_score"] for item in receipt["sources"]
    ]


def test_receipt_uses_approved_matched_concepts_field(tmp_path):
    (tmp_path / "repository_adapter.py").write_text("VALUE = 1\n")
    receipt = _adapt(tmp_path)
    ranking = receipt["path_ranking"]["phase1_candidates"][0]
    source = receipt["sources"][0]
    assert "matched_concepts" in ranking
    assert "matching_tokens" not in ranking
    assert "matched_concepts" in source
    assert "matching_tokens" not in source


def test_ambiguous_generic_and_uninterpreted_relevance_never_authorizes(tmp_path):
    (tmp_path / "repository_adapter_a.py").write_text("def inspect(): pass\n")
    (tmp_path / "repository_adapter_b.py").write_text("def inspect(): pass\n")
    receipt = _adapt(tmp_path)
    assert "AMBIGUOUS_RELEVANCE" in receipt["unknowns"]
    assert "SEMANTIC_RELEVANCE_UNINTERPRETED" in receipt["unknowns"]
    assert all(item["authorizing"] is False for item in receipt["candidates"])

    generic = _adapt(tmp_path, question="which source is safe?", context={
        "target": "hermes-static",
        "load_bearing_needs": [{"need_id": "need-inspect", "statement": "inspect source"}],
    })
    assert "INSUFFICIENT_RELEVANCE" in generic["unknowns"]


def test_context_rejects_injected_answers_and_receipt_has_closed_portable_shape(tmp_path):
    (tmp_path / "repository_adapter.py").write_text("def inspect_repository(): pass\n")
    for field in ("paths", "capabilities", "rank", "answer"):
        hostile = copy.deepcopy(CONTEXT)
        hostile[field] = []
        with pytest.raises(ValueError) as caught:
            _adapt(tmp_path, context=hostile)
        assert caught.value.args == ("TARGET_CONTEXT_SHAPE",)

    receipt = _adapt(tmp_path)
    assert set(receipt) == {
        "adapter_id", "adapter_version", "target", "captured_at", "freshness",
        "evidence_class", "source_binding", "inventory",
        "sources", "path_ranking", "dependencies", "exclusions",
        "enumeration_truncated", "uninspected_surfaces", "unknowns",
        "limitations", "candidates",
    }
    assert str(tmp_path) not in repr(receipt)
    assert receipt["sources"][0]["sha256"] == hashlib.sha256(
        (tmp_path / "repository_adapter.py").read_bytes()
    ).hexdigest()
    assert receipt["sources"][0]["regular_file"] is True
    assert receipt["sources"][0]["confined"] is True
    assert receipt["sources"][0]["race_checked"] is True


def test_receipt_validation_is_closed_fresh_target_bound_and_never_rereads(
    tmp_path, monkeypatch,
):
    source = tmp_path / "repository_adapter.py"
    source.write_text("def inspect_repository(): pass\n")
    receipt = _adapt(tmp_path)
    envelope = {
        "target_harness": {"target": "hermes-static"},
        "inferred_needs_constraints": [{
            "need_id": "need-inspect",
            "statement": "inspect repository adapter source",
            "load_bearing": True,
            "evidence_refs": ["ev-need"],
        }],
    }
    from rerg.path_query import MapBindingError, _validate_adapter_receipt

    def forbidden(*_args, **_kwargs):
        raise AssertionError("receipt validation reread the repository")

    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    _validate_adapter_receipt(copy.deepcopy(receipt), target=envelope["target_harness"]["target"], now=NOW,
    question="Which repository adapter source is relevant?",
    need_ids=[need["need_id"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
    statements=[need["statement"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],)

    assert [source["relative_posix_path"] for source in receipt["sources"]] == [
        "repository_adapter.py"
    ]
    assert receipt["evidence_class"] == "implementation_source"

    mutations = []
    extra = copy.deepcopy(receipt)
    extra["target_repository_root"] = str(tmp_path)
    mutations.append(extra)
    stale = copy.deepcopy(receipt)
    stale["captured_at"] = "2026-08-31T00:00:00Z"
    mutations.append(stale)
    wrong_target = copy.deepcopy(receipt)
    wrong_target["target"] = "other"
    mutations.append(wrong_target)
    tampered = copy.deepcopy(receipt)
    tampered["candidates"][0]["sha256"] = "0" * 64
    mutations.append(tampered)
    for changed in mutations:
        with pytest.raises(MapBindingError) as caught:
            _validate_adapter_receipt(
                changed, target=envelope["target_harness"]["target"], now=NOW,
                question="Which repository adapter source is relevant?",
                need_ids=[need["need_id"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
                statements=[need["statement"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
            )
        assert caught.value.reasons == ("MAP_BINDING",)


def test_receipt_validation_rederives_concepts_from_current_controller_inputs(
    tmp_path,
):
    (tmp_path / "repository_adapter.py").write_text("VALUE = 1\n")
    receipt = _adapt(tmp_path)
    envelope = {
        "target_harness": {"target": "hermes-static"},
        "inferred_needs_constraints": [{
            "need_id": "need-inspect",
            "statement": "inspect repository adapter source",
            "load_bearing": True,
            "evidence_refs": ["ev-need"],
        }],
    }
    from rerg.path_query import MapBindingError, _validate_adapter_receipt

    with pytest.raises(MapBindingError) as caught:
        _validate_adapter_receipt(
            receipt, target=envelope["target_harness"]["target"], now=NOW,
            question="Where is the unrelated scheduler?",
            need_ids=[need["need_id"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
            statements=[need["statement"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
        )
    assert caught.value.reasons == ("MAP_BINDING",)


def test_receipt_validation_recomputes_suffix_language_even_when_resealed(
    tmp_path, monkeypatch,
):
    (tmp_path / "repository_adapter.ts").write_text("export const value = true;\n")
    module = importlib.import_module("rerg.repository_target_adapter")
    monkeypatch.setattr(module, "_source_facts", lambda _relative, _data: {
        "language": "typescript",
        "status": "PARSED",
        "symbols": ["value"],
        "imports": [],
        "literal_tokens": [],
        "unknowns": [],
    })
    receipt = _adapt(tmp_path)
    changed = copy.deepcopy(receipt)
    source = changed["sources"][0]
    source["language"] = "javascript"
    envelope = {
        "target_harness": {"target": "hermes-static"},
        "inferred_needs_constraints": [{
            "need_id": "need-inspect",
            "statement": "inspect repository adapter source",
            "load_bearing": True,
            "evidence_refs": ["ev-need"],
        }],
    }
    from rerg.path_query import MapBindingError, _validate_adapter_receipt

    with pytest.raises(MapBindingError) as caught:
        _validate_adapter_receipt(
            changed, target=envelope["target_harness"]["target"], now=NOW,
            question="Which repository adapter source is relevant?",
            need_ids=[need["need_id"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
            statements=[need["statement"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
        )
    assert caught.value.reasons == ("MAP_BINDING",)


def test_receipt_validation_recomputes_dependency_edges_from_declared_imports(
    tmp_path, monkeypatch,
):
    (tmp_path / "repository_adapter.ts").write_text(
        "import './adapter_dependency';\nexport const value = true;\n"
    )
    (tmp_path / "adapter_dependency.ts").write_text("export const dep = true;\n")
    forged = tmp_path / "forged_dependency.ts"
    forged.write_text("export const forged = true;\n")
    module = importlib.import_module("rerg.repository_target_adapter")
    def source_facts(relative, _data):
        return {
            "language": "typescript",
            "status": "PARSED",
            "symbols": ["value"],
            "imports": (
                ["./adapter_dependency"]
                if relative == "repository_adapter.ts"
                else []
            ),
            "literal_tokens": [],
            "unknowns": [],
        }

    monkeypatch.setattr(module, "_source_facts", source_facts)
    receipt = _adapt(tmp_path)
    assert receipt["dependencies"]["inferred"] == [{
        "source_path": "repository_adapter.ts",
        "dependency_path": "adapter_dependency.ts",
        "sha256": hashlib.sha256(
            (tmp_path / "adapter_dependency.ts").read_bytes()
        ).hexdigest(),
        "need_ids": ["need-inspect"],
    }]

    changed = copy.deepcopy(receipt)
    forged_sha = hashlib.sha256(forged.read_bytes()).hexdigest()
    changed["dependencies"]["observed"] = [
        item for item in changed["dependencies"]["observed"]
        if item.get("kind") != "source"
        or item.get("path") != "adapter_dependency.ts"
    ]
    changed["dependencies"]["observed"].append({
        "kind": "source",
        "path": "forged_dependency.ts",
        "sha256": forged_sha,
        "need_ids": ["need-inspect"],
    })
    changed["dependencies"]["inferred"][0] = {
        "source_path": "repository_adapter.ts",
        "dependency_path": "forged_dependency.ts",
        "sha256": forged_sha,
        "need_ids": ["need-inspect"],
    }
    envelope = {
        "target_harness": {"target": "hermes-static"},
        "inferred_needs_constraints": [{
            "need_id": "need-inspect",
            "statement": "inspect repository adapter source",
            "load_bearing": True,
            "evidence_refs": ["ev-need"],
        }],
    }
    from rerg.path_query import MapBindingError, _validate_adapter_receipt

    with pytest.raises(MapBindingError) as caught:
        _validate_adapter_receipt(
            changed, target=envelope["target_harness"]["target"], now=NOW,
            question="Which repository adapter source is relevant?",
            need_ids=[need["need_id"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
            statements=[need["statement"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
        )
    assert caught.value.reasons == ("MAP_BINDING",)


def test_parser_facts_are_digest_bound_self_consistency_not_authentication(
    tmp_path, monkeypatch,
):
    (tmp_path / "repository_adapter.py").write_text(
        "def inspect_repository(): return 'adapter source'\n"
    )
    receipt = _adapt(tmp_path)
    changed = copy.deepcopy(receipt)
    changed["sources"][0]["symbols"] = ["valid_looking_alternative"]
    changed["sources"][0]["literal_tokens"] = ["valid", "looking"]
    envelope = {
        "target_harness": {"target": "hermes-static"},
        "inferred_needs_constraints": [{
            "need_id": "need-inspect",
            "statement": "inspect repository adapter source",
            "load_bearing": True,
            "evidence_refs": ["ev-need"],
        }],
    }
    from rerg.path_query import _validate_adapter_receipt

    def forbidden(*_args, **_kwargs):
        raise AssertionError("validator must not authenticate by rereading source")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    _validate_adapter_receipt(changed, target=envelope["target_harness"]["target"], now=NOW,
    question="Which repository adapter source is relevant?",
    need_ids=[need["need_id"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
    statements=[need["statement"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],)

    assert changed["evidence_class"] == "implementation_source"


def test_component_exclusions_have_identical_adapter_and_validator_semantics(tmp_path):
    (tmp_path / "todo.py").write_text("TODO = 1\n")
    nested = tmp_path / "node_modules" / "todo.py"
    nested.parent.mkdir()
    nested.write_text("TODO = 2\n")
    receipt = _adapt(
        tmp_path,
        question="todo",
        context={
            "target": "hermes-static",
            "load_bearing_needs": [{
                "need_id": "need-inspect", "statement": "todo",
            }],
        },
    )
    envelope = {
        "target_harness": {"target": "hermes-static"},
        "inferred_needs_constraints": [{
            "need_id": "need-inspect",
            "statement": "todo",
            "load_bearing": True,
            "evidence_refs": ["ev-need"],
        }],
    }
    from rerg.path_query import _validate_adapter_receipt

    _validate_adapter_receipt(receipt, target=envelope["target_harness"]["target"], now=NOW,
    question="todo",
    need_ids=[need["need_id"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
    statements=[need["statement"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],)

    assert [source["relative_posix_path"] for source in receipt["sources"]] == ["todo.py"]
    assert receipt["exclusions"] == [{
        "category": "runtime", "relative_posix_path": "node_modules",
    }]


def test_status_only_unavailable_records_validate_through_receipt_boundary(tmp_path):
    (tmp_path / "todo.py").write_text("TODO = 1\n")
    (tmp_path / "deleted.py").write_text("DELETE = 1\n")
    _initialize_git_fixture(tmp_path)
    subprocess.run(
        ["git", "rm", "-q", "--", "deleted.py"], cwd=tmp_path, check=True,
    )
    receipt = _adapt(
        tmp_path,
        question="todo",
        context={
            "target": "hermes-static",
            "load_bearing_needs": [{
                "need_id": "need-inspect", "statement": "todo",
            }],
        },
    )
    envelope = {
        "target_harness": {"target": "hermes-static"},
        "inferred_needs_constraints": [{
            "need_id": "need-inspect",
            "statement": "todo",
            "load_bearing": True,
            "evidence_refs": ["ev-need"],
        }],
    }
    from rerg.path_query import _validate_adapter_receipt

    _validate_adapter_receipt(receipt, target=envelope["target_harness"]["target"], now=NOW,
    question="todo",
    need_ids=[need["need_id"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
    statements=[need["statement"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],)

    assert receipt["uninspected_surfaces"] == ["deleted.py"]
    assert "UNAVAILABLE_SURFACE" in receipt["limitations"]


def test_validator_rejects_selected_safe_read_failure_missing_from_partition(
    tmp_path,
):
    (tmp_path / "repository_adapter.py").write_bytes(
        b"#" + b"x" * (4 * 1024 * 1024)
    )
    receipt = _adapt(tmp_path)
    assert receipt["uninspected_surfaces"] == ["repository_adapter.py"]
    receipt["uninspected_surfaces"] = []
    envelope = {
        "target_harness": {"target": "hermes-static"},
        "inferred_needs_constraints": [{
            "need_id": "need-inspect",
            "statement": "inspect repository adapter source",
            "load_bearing": True,
            "evidence_refs": ["ev-need"],
        }],
    }
    from rerg.path_query import MapBindingError, _validate_adapter_receipt

    with pytest.raises(MapBindingError) as caught:
        _validate_adapter_receipt(
            receipt, target=envelope["target_harness"]["target"], now=NOW,
            question="Which repository adapter source is relevant?",
            need_ids=[need["need_id"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
            statements=[need["statement"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
        )
    assert caught.value.reasons == ("MAP_BINDING",)


def test_receipt_validation_enforces_declared_source_import_bound(tmp_path):
    (tmp_path / "repository_adapter.py").write_text("VALUE = 1\n")
    receipt = _adapt(tmp_path)
    receipt["sources"][0]["imports"] = [
        f"module_{index}" for index in range(129)
    ]
    envelope = {
        "target_harness": {"target": "hermes-static"},
        "inferred_needs_constraints": [{
            "need_id": "need-inspect",
            "statement": "inspect repository adapter source",
            "load_bearing": True,
            "evidence_refs": ["ev-need"],
        }],
    }
    from rerg.path_query import MapBindingError, _validate_adapter_receipt

    with pytest.raises(MapBindingError) as caught:
        _validate_adapter_receipt(
            receipt, target=envelope["target_harness"]["target"], now=NOW,
            question="Which repository adapter source is relevant?",
            need_ids=[need["need_id"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
            statements=[need["statement"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
        )
    assert caught.value.reasons == ("MAP_BINDING",)


@pytest.mark.parametrize(
    "relation",
    [
        "phase1_path_score",
        "source_phase1_path",
        "source_phase1_score",
        "source_phase1_tokens",
        "source_language",
        "source_parser_facts_after_error",
        "candidate_source_path",
        "candidate_source_digest",
        "candidate_derived_score",
        "candidate_authorizing",
        "dependency_source_digest",
        "duplicate_phase1_path",
        "duplicate_source_path",
        "duplicate_candidate_path",
        "source_sort_order",
        "candidate_exact_set",
        "uninspected_sort_order",
        "dependency_unknown_consistency",
        "dependency_need_ids",
        "inferred_dependency_unobserved",
        "semantic_unknown_consistency",
        "inventory_digest_binding",
        "non_utf8_receipt_path",
    ],
)
def test_receipt_validation_rejects_product_verifiable_relation_tampering(
    tmp_path, relation,
):
    source = tmp_path / "repository_adapter.py"
    source.write_text("def inspect_repository(): return 'adapter source'\n")
    second = tmp_path / "repository_source.ts"
    second.write_text("export const repositorySource = true;\n")
    if relation == "inferred_dependency_unobserved":
        source = tmp_path / "repository_adapter.ts"
        source.write_text(
            "import './repository_source';\n"
            "export const repositoryAdapter = true;\n"
        )
    receipt = _adapt(tmp_path)
    envelope = {
        "target_harness": {"target": "hermes-static"},
        "inferred_needs_constraints": [{
            "need_id": "need-inspect",
            "statement": "inspect repository adapter source",
            "load_bearing": True,
            "evidence_refs": ["ev-need"],
        }],
    }
    from rerg.path_query import MapBindingError, _validate_adapter_receipt

    changed = copy.deepcopy(receipt)
    if relation == "phase1_path_score":
        phase1 = changed["path_ranking"]["phase1_candidates"][0]
        source = changed["sources"][0]
        phase1["matched_concepts"] = ["inspect"]
        source["matched_concepts"] = ["inspect"]
    elif relation == "source_phase1_path":
        changed["sources"][0]["relative_posix_path"] = "forged.py"
    elif relation == "source_phase1_score":
        changed["sources"][0]["path_score"] += 1
    elif relation == "source_phase1_tokens":
        changed["sources"][0]["matched_concepts"] = ["forged"]
    elif relation == "source_language":
        changed["sources"][0]["language"] = "go"
    elif relation == "source_parser_facts_after_error":
        changed["sources"][0]["status"] = "SYNTAX_ERROR"
        changed["sources"][0]["symbols"] = ["forged"]
    elif relation == "candidate_source_path":
        changed["candidates"][0]["relative_posix_path"] = "forged.py"
    elif relation == "candidate_source_digest":
        changed["candidates"][0]["sha256"] = "0" * 64
    elif relation == "candidate_derived_score":
        changed["candidates"][0]["score"] += 1
    elif relation == "candidate_authorizing":
        changed["candidates"][0]["authorizing"] = True
    elif relation == "dependency_source_digest":
        source_digest = changed["sources"][0]["sha256"]
        changed["dependencies"]["observed"].append({
            "kind": "source",
            "path": changed["sources"][0]["relative_posix_path"],
            "sha256": ("0" if source_digest[0] != "0" else "1") + source_digest[1:],
            "need_ids": ["need-inspect"],
        })
    elif relation == "duplicate_phase1_path":
        changed["path_ranking"]["phase1_candidates"].append(
            copy.deepcopy(changed["path_ranking"]["phase1_candidates"][-1])
        )
    elif relation == "duplicate_source_path":
        changed["sources"].append(copy.deepcopy(changed["sources"][-1]))
    elif relation == "duplicate_candidate_path":
        changed["candidates"].append(copy.deepcopy(changed["candidates"][-1]))
    elif relation == "source_sort_order":
        changed["sources"].reverse()
    elif relation == "candidate_exact_set":
        changed["candidates"] = changed["candidates"][:-1]
    elif relation == "uninspected_sort_order":
        changed["uninspected_surfaces"] = ["z.py", "a.py"]
    elif relation == "dependency_unknown_consistency":
        changed["dependencies"]["unknowns"].append({
            "reason": "DYNAMIC_IMPORT",
            "need_ids": ["need-inspect"],
        })
    elif relation == "dependency_need_ids":
        changed["dependencies"]["observed"][0]["need_ids"] = ["forged-need"]
    elif relation == "inferred_dependency_unobserved":
        dependency_path = changed["dependencies"]["inferred"][0][
            "dependency_path"
        ]
        changed["dependencies"]["observed"] = [
            item for item in changed["dependencies"]["observed"]
            if item.get("kind") != "source"
            or item.get("path") != dependency_path
        ]
    elif relation == "semantic_unknown_consistency":
        changed["unknowns"].remove("SEMANTIC_RELEVANCE_UNINTERPRETED")
        changed["limitations"] = list(changed["unknowns"])
    elif relation == "inventory_digest_binding":
        changed["inventory"]["records"][0]["status"] = " M"
    elif relation == "non_utf8_receipt_path":
        original_path = changed["sources"][0]["relative_posix_path"]
        unsafe_path = "repository_\udcff_adapter.py"
        changed["path_ranking"]["phase1_candidates"][0][
            "relative_posix_path"
        ] = unsafe_path
        changed["sources"][0]["relative_posix_path"] = unsafe_path
        for candidate in changed["candidates"]:
            if candidate["relative_posix_path"] == original_path:
                candidate["relative_posix_path"] = unsafe_path
        for item in changed["dependencies"]["observed"]:
            if item.get("path") == original_path:
                item["path"] = unsafe_path

    with pytest.raises(MapBindingError) as caught:
        _validate_adapter_receipt(
            changed, target=envelope["target_harness"]["target"], now=NOW,
            question="Which repository adapter source is relevant?",
            need_ids=[need["need_id"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
            statements=[need["statement"] for need in envelope["inferred_needs_constraints"] if need["load_bearing"]],
        )
    assert caught.value.reasons == ("MAP_BINDING",)




















# Injected leads below prove admission only; content-search tests live in host workflow.
def _followup_case(root, bodies=None):
    (root / "repository_adapter.py").write_text("def inspect_repository(): return 1\n")
    for path, data in (bodies or {"z.py": b"def unusual(): return 2\n"}).items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_bytes(data)
    return _adapt(root)


def _followup(root, prior, paths, now=NOW):
    return _adapter()(
        target_context=copy.deepcopy(CONTEXT), target_repository_root=root,
        question="Which repository adapter source is relevant?", now=now,
        followup={"prior_receipt": prior, "missing_fact": "Where is the unusual behavior implemented?",
                  "need_ids": ["need-inspect"], "paths": paths},
    )


def _validate_followup(receipt):
    from rerg.path_query import _validate_adapter_receipt
    _validate_adapter_receipt(receipt, target=CONTEXT["target"], now=receipt["captured_at"],
                              need_ids=["need-inspect"], question="Which repository adapter source is relevant?",
                              statements=[CONTEXT["load_bearing_needs"][0]["statement"]])


@pytest.mark.parametrize("count", [0, 1, 4])
def test_followup_adds_without_displacing_initial_sources(tmp_path, count):
    bodies = {f"z{i}.py": b"def unusual(): return 2\n" for i in range(4)}
    prior = _followup_case(tmp_path, bodies)
    assert len(prior["sources"]) == 1
    result = _followup(tmp_path, prior, list(bodies)[:count], "2026-09-02T00:00:00Z")
    assert result["receipt"]["sources"] == prior["sources"]
    assert "followup" in result["receipt"]
    assert len(result["receipt"]["followup"]["sources"]) == count
    assert len(result["passages"]) == 1 + count
    assert all(p["artifact"]["captured_at"] == result["receipt"]["captured_at"] for p in result["passages"])
    _validate_followup(result["receipt"])
    with pytest.raises(ValueError):
        _followup(tmp_path, result["receipt"], [])


@pytest.mark.parametrize("paths", [["z.py"]*2, [f"z{i}.py" for i in range(5)], ["../z.py"],
                                   ["/z.py"], ["a\\z.py"], ["./z.py"], ["repository_adapter.py"]])
def test_followup_rejects_invalid_leads_before_reads(tmp_path, monkeypatch, paths):
    prior = _followup_case(tmp_path)
    module = importlib.import_module("rerg.repository_target_adapter")
    def unreadable(*args, **kwargs):
        pytest.fail("invalid followup must be rejected before source reads")
    monkeypatch.setattr(module, "_read_regular_source", unreadable)
    with pytest.raises(ValueError):
        _followup(tmp_path, prior, paths)


@pytest.mark.parametrize("size", [1_048_576, 1_048_577])
def test_followup_byte_boundary_and_failure_charge(tmp_path, size):
    prior = _followup_case(tmp_path, {"z.txt": b"x" * size})
    result = _followup(tmp_path, prior, ["z.txt"])
    followup = result["receipt"]["followup"]
    assert followup["total_bytes"] == 1_048_576
    assert len(followup["sources"]) == (size == 1_048_576)
    assert bool(result["failures"]) == (size > 1_048_576)
    _validate_followup(result["receipt"])


@pytest.mark.parametrize("path,body", [(".env", b"secret"), ("eval/x.py", b"x=1"),
                                      ("z.py", b"password = 'unsafe'"), ("z.py", b"\xff")])
def test_followup_unsafe_or_excluded_evidence_is_not_admitted(tmp_path, path, body):
    prior = _followup_case(tmp_path, {path: body})
    result = _followup(tmp_path, prior, [path])
    assert not result["receipt"]["followup"]["sources"]
    assert result["failures"]
    assert all(p["source_path"] != path for p in result["passages"])
    assert "unsafe" not in repr(result["failures"])
    _validate_followup(result["receipt"])


@pytest.mark.parametrize("reason,code", [
    ("SOURCE_CHANGED", "FOLLOWUP_SOURCE_CHANGED"),
    ("NOT_REGULAR_FILE", "FOLLOWUP_READ_FAILED"),
])
def test_followup_read_failure_stops_and_charges_remaining_budget(tmp_path, monkeypatch, reason, code):
    prior = _followup_case(tmp_path, {"z.py": b"x=1", "zz.py": b"x=2"})
    module = importlib.import_module("rerg.repository_target_adapter")
    original = module._read_regular_source
    attempts = []
    def fail_after_read(root, path, budget):
        result = original(root, path, budget)
        if path == "z.py":
            attempts.append(path)
            raise ValueError(reason)
        assert path != "zz.py"
        return result
    monkeypatch.setattr(module, "_read_regular_source", fail_after_read)
    result = _followup(tmp_path, prior, ["z.py", "zz.py"])
    assert attempts == ["z.py"]
    assert result["receipt"]["followup"]["total_bytes"] == 1_048_576
    assert result["receipt"]["followup"]["failures"][0] == {
        "path": "z.py", "code": code, "bytes": 1_048_576,
    }
    assert not result["receipt"]["followup"]["sources"]
    _validate_followup(result["receipt"])


@pytest.mark.parametrize("missing_fact", ["", "   ", "\t\n"])
def test_followup_requires_a_named_nonblank_missing_fact(tmp_path, monkeypatch, missing_fact):
    prior = _followup_case(tmp_path)
    module = importlib.import_module("rerg.repository_target_adapter")
    reads = []
    original = module._read_regular_source
    def read(root, path, budget):
        reads.append(path)
        return original(root, path, budget)
    monkeypatch.setattr(module, "_read_regular_source", read)
    with pytest.raises(ValueError):
        _adapter()(
            target_context=copy.deepcopy(CONTEXT), target_repository_root=tmp_path,
            question="Which repository adapter source is relevant?", now=NOW,
            followup={"prior_receipt": prior, "missing_fact": missing_fact,
                      "need_ids": ["need-inspect"], "paths": ["z.py"]},
        )
    assert reads == []


@pytest.mark.parametrize("drift", ["bytes", "inventory", "future"])
def test_followup_stops_on_prior_binding_or_dirty_byte_drift(tmp_path, drift):
    prior = _followup_case(tmp_path)
    if drift == "bytes":
        (tmp_path / "repository_adapter.py").write_text("def inspect_repository(): return 9\n")
    elif drift == "inventory":
        (tmp_path / "added.py").write_text("x=1")
    with pytest.raises(ValueError):
        _followup(tmp_path, prior, ["z.py"], "2026-08-31T00:00:00Z" if drift == "future" else NOW)


def test_followup_imports_do_not_expand_dependency_frontier(tmp_path):
    prior = _followup_case(tmp_path, {"z.py": b"import zz\n", "zz.py": b"x=1\n"})
    result = _followup(tmp_path, prior, ["z.py"])
    assert result["receipt"]["followup"]["sources"]
    assert result["receipt"]["dependencies"] == prior["dependencies"]
    assert "zz.py" not in {p["source_path"] for p in result["passages"]}


@pytest.mark.parametrize("field", ["total_bytes", "paths", "prior_receipt", "sources"])
def test_followup_receipt_tampering_fails_pure_validation(tmp_path, monkeypatch, field):
    prior = _followup_case(tmp_path)
    receipt = _followup(tmp_path, prior, ["z.py"])["receipt"]
    _validate_followup(receipt)
    changed = copy.deepcopy(receipt)
    section = changed["followup"]
    if field == "total_bytes": section[field] += 1
    elif field == "paths": section[field] = ["not-in-inventory.py"]
    elif field == "prior_receipt": section[field]["followup"] = {}
    else: section[field][0]["relative_posix_path"] = "forged.py"
    def no_io(*args, **kwargs): pytest.fail("pure validator performed I/O")
    monkeypatch.setattr(Path, "read_bytes", no_io)
    monkeypatch.setattr(subprocess, "run", no_io)
    _validate_followup(receipt)
    with pytest.raises(ValueError): _validate_followup(changed)
