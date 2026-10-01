"""Atomic, bounded Git worktree inventory for controller-bound target scopes."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import subprocess
import time
from typing import Any

_SCHEMA_VERSION = "rerg-git-worktree-inventory/v1"
_SCOPE_SCHEMA = "rerg-git-scope-identity/v1"
_STDOUT_LIMIT = 8 * 1024 * 1024
_STDERR_LIMIT = 64 * 1024
_FILTER_CONFIG_STDOUT_LIMIT = 64 * 1024
_MAX_FILTER_CONFIG_KEYS = 128
_MAX_FILTER_DRIVERS = 32
_TIMEOUT_SECONDS = 5.0
_CLEANUP_TIMEOUT_SECONDS = 1.0
_OID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_STAGE = re.compile(r"(\d{6}) ([0-9a-f]{40}(?:[0-9a-f]{24})?) ([0-3])\t(.+)", re.DOTALL)
_FILTER_CONFIG_KEY = re.compile(
    r"filter\.([A-Za-z0-9][A-Za-z0-9_-]{0,63})\."
    r"(clean|smudge|process|required)\Z",
)
_GIT_CONFIG_OVERRIDES = (
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.pager=cat",
    "-c", "pager.status=false",
    "-c", "diff.renames=false",
    "-c", "diff.renameLimit=0",
    "-c", "status.renames=false",
)
_FILTER_CONFIG_COMMAND = ("config", "--local", "--name-only", "-z", "--list")
_STATE_COMMANDS = (
    ("rev-parse", "--verify", "HEAD"),
    ("ls-files", "--stage", "-z", "--"),
    ("ls-files", "--others", "--exclude-standard", "-z", "--"),
    (
        "status", "--porcelain=v1", "-z", "--untracked-files=all",
        "--ignore-submodules=none", "--no-renames", "--",
    ),
)
_ENV = {
    "LC_ALL": "C",
    "LANG": "C",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_PAGER": "cat",
}


class GitInventoryError(ValueError):
    """An atomic inventory failure with a stable machine-readable reason."""


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=_CLEANUP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        pass


def _execute_bounded(
    command: tuple[str, ...], *, cwd: Path, stdout_limit: int,
    stderr_limit: int, timeout: float,
) -> tuple[bytes, bytes, int]:
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
    except OSError:
        raise GitInventoryError("GIT_NONZERO") from None
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    streams = {
        process.stdout: (bytearray(), stdout_limit, "GIT_STDOUT_LIMIT"),
        process.stderr: (bytearray(), stderr_limit, "GIT_STDERR_LIMIT"),
    }
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_group(process)
                raise GitInventoryError("GIT_TIMEOUT")
            events = selector.select(remaining)
            if not events:
                _terminate_group(process)
                raise GitInventoryError("GIT_TIMEOUT")
            for key, _ in events:
                stream = key.fileobj
                chunk = os.read(stream.fileno(), 65_536)
                if not chunk:
                    selector.unregister(stream)
                    continue
                target, limit, reason = streams[stream]
                target.extend(chunk)
                if len(target) > limit:
                    _terminate_group(process)
                    raise GitInventoryError(reason)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_group(process)
            raise GitInventoryError("GIT_TIMEOUT")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _terminate_group(process)
            raise GitInventoryError("GIT_TIMEOUT") from None
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return bytes(streams[process.stdout][0]), bytes(streams[process.stderr][0]), returncode


def _run_git(
    argv: tuple[str, ...], *, cwd: Path, config_overrides: tuple[str, ...] = (),
) -> bytes:
    stdout_limit = (
        _FILTER_CONFIG_STDOUT_LIMIT
        if argv == _FILTER_CONFIG_COMMAND else _STDOUT_LIMIT
    )
    stdout, _stderr, returncode = _execute_bounded(
        ("git", "--no-pager", *_GIT_CONFIG_OVERRIDES, *config_overrides, *argv),
        cwd=cwd,
        stdout_limit=stdout_limit,
        stderr_limit=_STDERR_LIMIT,
        timeout=_TIMEOUT_SECONDS,
    )
    if returncode != 0:
        raise GitInventoryError("GIT_NONZERO")
    return stdout


def _filter_config_keys(data: bytes) -> tuple[bytes, list[str]]:
    """Return exact local filter-driver keys that can be disabled safely.

    Git inventory is path-based and cannot detect malicious A→B→A worktree
    swaps outside observed state changes. This filter closure only prevents
    repository-local content-conversion helpers from executing while inventory
    asks Git about tracked worktree state.
    """
    if not data:
        return b"", []
    if not data.endswith(b"\0"):
        raise GitInventoryError("GIT_FILTER_CONFIG_MALFORMED")
    raw_keys = data[:-1].split(b"\0")
    if len(raw_keys) > _MAX_FILTER_CONFIG_KEYS:
        raise GitInventoryError("GIT_FILTER_CONFIG_LIMIT")
    filtered: list[bytes] = []
    drivers: set[str] = set()
    for raw_key in raw_keys:
        if not raw_key:
            raise GitInventoryError("GIT_FILTER_CONFIG_MALFORMED")
        try:
            key = raw_key.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise GitInventoryError("GIT_FILTER_CONFIG_MALFORMED") from None
        if not key.startswith("filter."):
            continue
        match = _FILTER_CONFIG_KEY.fullmatch(key)
        if match is None:
            raise GitInventoryError("GIT_FILTER_CONFIG_MALFORMED")
        filtered.append(raw_key)
        drivers.add(match.group(1))
    if len(drivers) > _MAX_FILTER_DRIVERS:
        raise GitInventoryError("GIT_FILTER_CONFIG_LIMIT")
    return (b"".join(key + b"\0" for key in filtered), sorted(drivers))


def _filter_disable_overrides(drivers: list[str]) -> tuple[str, ...]:
    overrides: list[str] = []
    for driver in drivers:
        if _FILTER_CONFIG_KEY.fullmatch(f"filter.{driver}.clean") is None:
            raise GitInventoryError("GIT_FILTER_CONFIG_MALFORMED")
        overrides.extend([
            "-c", f"filter.{driver}.clean=",
            "-c", f"filter.{driver}.smudge=",
            "-c", f"filter.{driver}.process=",
            "-c", f"filter.{driver}.required=false",
        ])
    return tuple(overrides)


def _decode(data: bytes, reason: str = "GIT_INVENTORY_MALFORMED") -> str:
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise GitInventoryError(reason) from None


def _single_line(data: bytes) -> str:
    text = _decode(data, "TARGET_WORKTREE_BINDING")
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise GitInventoryError("TARGET_WORKTREE_BINDING")
    return lines[0]


def _records(data: bytes) -> list[str]:
    if not data:
        return []
    if not data.endswith(b"\0"):
        raise GitInventoryError("GIT_INVENTORY_MALFORMED")
    raw = data[:-1].split(b"\0")
    if any(not item for item in raw):
        raise GitInventoryError("GIT_INVENTORY_MALFORMED")
    return [_decode(item) for item in raw]


def _normalize(path: str) -> str:
    try:
        path.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise GitInventoryError("GIT_INVENTORY_MALFORMED") from None
    normalized = PurePosixPath(path).as_posix()
    if (
        not path or "\x00" in path or "\\" in path
        or path.startswith(("/", "~"))
        or normalized != path
        or any(part in {"", ".", ".."} for part in PurePosixPath(path).parts)
    ):
        raise GitInventoryError("GIT_INVENTORY_MALFORMED")
    return normalized


def _project(path: str, scope_prefix: str) -> str | None:
    normalized = _normalize(path)
    if not scope_prefix:
        return normalized
    prefix = scope_prefix + "/"
    if normalized == scope_prefix:
        raise GitInventoryError("GIT_INVENTORY_MALFORMED")
    if not normalized.startswith(prefix):
        return None
    projected = normalized[len(prefix):]
    return _normalize(projected)


def _parse_status_records(data: bytes) -> list[dict[str, str]]:
    values = _records(data)
    result: list[dict[str, str]] = []
    index = 0
    while index < len(values):
        record = values[index]
        if len(record) < 4 or record[2] != " ":
            raise GitInventoryError("GIT_INVENTORY_MALFORMED")
        code = record[:2]
        if code in {"DD", "AU", "UD", "UA", "DU", "AA", "UU"}:
            raise GitInventoryError("GIT_UNMERGED")
        index_code, worktree_code = code
        if not (
            code in {"??", "!!"}
            or (index_code in " MADT" and worktree_code in " MDT" and code != "  ")
        ):
            raise GitInventoryError("GIT_INVENTORY_MALFORMED")
        path = _normalize(record[3:])
        index += 1
        result.append({"path": path, "code": code})
    return result


def _detect_cross_scope_path_state(
    status: list[dict[str, str]], scope_prefix: str,
) -> None:
    if not scope_prefix:
        return
    inside_add = inside_delete = outside_add = outside_delete = False
    for item in status:
        projected = _project(item["path"], scope_prefix)
        staged_code = item["code"][0]
        if staged_code == "A":
            if projected is None:
                outside_add = True
            else:
                inside_add = True
        elif staged_code == "D":
            if projected is None:
                outside_delete = True
            else:
                inside_delete = True
    if (inside_add and outside_delete) or (inside_delete and outside_add):
        raise GitInventoryError("CROSS_SCOPE_PATH_STATE")


def _project_status(
    status: list[dict[str, str]], scope_prefix: str,
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for item in status:
        projected = _project(item["path"], scope_prefix)
        if projected is not None:
            result.append({"path": projected, "code": item["code"]})
    unique: dict[str, str] = {}
    for item in result:
        if item["path"] in unique and unique[item["path"]] != item["code"]:
            raise GitInventoryError("GIT_INVENTORY_MALFORMED")
        unique[item["path"]] = item["code"]
    return [
        {"path": path, "code": unique[path]}
        for path in sorted(unique, key=lambda value: value.encode("utf-8"))
    ]


def _collect_git_state(top: Path) -> tuple[bytes, bytes, bytes, bytes, bytes, list[str]]:
    try:
        raw_config = _run_git(_FILTER_CONFIG_COMMAND, cwd=top)
    except GitInventoryError as error:
        if str(error) == "GIT_STDOUT_LIMIT":
            raise GitInventoryError("GIT_FILTER_CONFIG_LIMIT") from None
        raise
    filtered_config, drivers = _filter_config_keys(raw_config)
    overrides = _filter_disable_overrides(drivers)
    state = tuple(
        _run_git(command, cwd=top, config_overrides=overrides)
        for command in _STATE_COMMANDS
    )
    return (filtered_config, *state, drivers)  # type: ignore[return-value]


def _stable_git_state(top: Path) -> tuple[bytes, bytes, bytes, bytes, bytes, list[str]]:
    first = _collect_git_state(top)
    try:
        second = _collect_git_state(top)
    except GitInventoryError as error:
        raise GitInventoryError(
            f"GIT_INVENTORY_SECOND_PASS_FAILED:{error}"
        ) from None
    if first[0] != second[0] or first[5] != second[5]:
        raise GitInventoryError("GIT_FILTER_CONFIG_CHANGED")
    if first[1:5] != second[1:5]:
        raise GitInventoryError("GIT_INVENTORY_CHANGED")
    return first


def collect_git_worktree_inventory(target_scope: str | Path) -> dict[str, Any]:
    """Collect one complete projected inventory or raise without partial output."""
    try:
        supplied = Path(target_scope)
        scope = supplied.resolve(strict=True)
    except (OSError, TypeError, ValueError):
        raise GitInventoryError("TARGET_WORKTREE_BINDING") from None
    if not scope.is_dir():
        raise GitInventoryError("TARGET_WORKTREE_BINDING")

    try:
        discovered = _single_line(
            _run_git(("rev-parse", "--show-toplevel"), cwd=scope)
        )
    except GitInventoryError as error:
        if str(error) in {"GIT_NONZERO", "TARGET_WORKTREE_BINDING"}:
            raise GitInventoryError("TARGET_WORKTREE_BINDING") from None
        raise
    discovered_path = Path(discovered)
    if not discovered_path.is_absolute():
        raise GitInventoryError("TARGET_WORKTREE_BINDING")
    try:
        top = discovered_path.resolve(strict=True)
        relative_scope = scope.relative_to(top)
    except (OSError, ValueError):
        raise GitInventoryError("TARGET_WORKTREE_BINDING") from None
    if not top.is_dir():
        raise GitInventoryError("TARGET_WORKTREE_BINDING")
    scope_prefix = "" if scope == top else relative_scope.as_posix()
    if scope_prefix:
        _normalize(scope_prefix)

    (
        raw_filter_config, raw_head, raw_staged, raw_untracked, raw_status,
        disabled_filter_drivers,
    ) = _stable_git_state(top)
    head_oid = _single_line(raw_head)
    if _OID.fullmatch(head_oid) is None:
        raise GitInventoryError("GIT_INVENTORY_MALFORMED")
    staged = _records(raw_staged)
    untracked = _records(raw_untracked)
    raw_status_records = _parse_status_records(raw_status)
    _detect_cross_scope_path_state(raw_status_records, scope_prefix)
    status = _project_status(raw_status_records, scope_prefix)
    status_by_path = {item["path"]: item["code"] for item in status}

    records: list[dict[str, Any]] = []
    exclusions: list[dict[str, str]] = []
    seen_top: set[str] = set()
    for raw in staged:
        match = _STAGE.fullmatch(raw)
        if match is None:
            raise GitInventoryError("GIT_INVENTORY_MALFORMED")
        mode, oid, stage_text, path = match.groups()
        normalized = _normalize(path)
        stage = int(stage_text)
        if stage != 0:
            raise GitInventoryError("GIT_UNMERGED")
        if normalized in seen_top:
            raise GitInventoryError("GIT_INVENTORY_MALFORMED")
        seen_top.add(normalized)
        projected = _project(normalized, scope_prefix)
        if projected is None:
            continue
        if mode in {"120000", "160000"}:
            exclusions.append({
                "path": projected,
                "category": "symlink" if mode == "120000" else "submodule",
            })
            continue
        if mode not in {"100644", "100755"}:
            raise GitInventoryError("GIT_INVENTORY_MALFORMED")
        code = status_by_path.get(projected, "  ")
        records.append({
            "path": projected,
            "tracking": "tracked",
            "mode": mode,
            "oid": oid,
            "stage": stage,
            "status": code,
            "availability": "missing" if "D" in code else "available",
        })

    for path in untracked:
        normalized = _normalize(path)
        if normalized in seen_top:
            raise GitInventoryError("GIT_INVENTORY_MALFORMED")
        seen_top.add(normalized)
        projected = _project(normalized, scope_prefix)
        if projected is None:
            continue
        records.append({
            "path": projected,
            "tracking": "untracked",
            "mode": None,
            "oid": None,
            "stage": None,
            "status": status_by_path.get(projected, "??"),
            "availability": "available",
        })

    accounted_paths = {
        item["path"] for item in records
    } | {
        item["path"] for item in exclusions
    }
    for item in status:
        if item["path"] in accounted_paths:
            continue
        if item["code"][0] != "D":
            raise GitInventoryError("GIT_INVENTORY_MALFORMED")
        records.append({
            "path": item["path"],
            "tracking": "status-only",
            "mode": None,
            "oid": None,
            "stage": None,
            "status": item["code"],
            "availability": "missing",
        })

    records.sort(key=lambda item: item["path"].encode("utf-8"))
    exclusions.sort(key=lambda item: item["path"].encode("utf-8"))
    if len({item["path"] for item in records + exclusions}) != len(records) + len(exclusions):
        raise GitInventoryError("GIT_INVENTORY_MALFORMED")
    dirty_paths = [item["path"] for item in status]
    scope_identity_sha256 = _canonical_sha256({
        "schema_version": _SCOPE_SCHEMA,
        "head_oid": head_oid,
        "scope_prefix": scope_prefix,
    })
    inventory_payload = {
        "schema_version": _SCHEMA_VERSION,
        "head_oid": head_oid,
        "scope_identity_sha256": scope_identity_sha256,
        "scope_prefix": scope_prefix,
        "records": records,
        "status": status,
        "exclusions": exclusions,
        "ignore_policy": "git-exclude-standard",
        "filter_config_keys_sha256": hashlib.sha256(
            raw_filter_config
        ).hexdigest(),
        "disabled_filter_drivers": disabled_filter_drivers,
    }
    return {
        **inventory_payload,
        "inventory_sha256": _canonical_sha256(inventory_payload),
        "worktree_state": "dirty" if dirty_paths else "clean",
        "dirty_paths": dirty_paths,
    }


__all__ = ["GitInventoryError", "collect_git_worktree_inventory"]
