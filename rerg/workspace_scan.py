"""Pure classification of visible workspace status entries."""

from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

_DEFAULTS = (".gjc", ".omx")


class WorkspaceScanError(ValueError):
    def __init__(self, *reasons: str) -> None:
        self.reasons = tuple(dict.fromkeys(reasons))
        super().__init__(";".join(self.reasons))


def _relative(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return False
    path = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return (
        not value.startswith(("/", "~/"))
        and not windows.drive
        and not windows.root
        and bool(path.parts)
        and all(part not in {".", ".."} for part in path.parts)
        and path.as_posix() == value
    )


def _validate_prefixes(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not all(_relative(item) for item in values):
        raise WorkspaceScanError("INVALID_ALLOWLIST")
    prefixes = tuple(values)
    if len(prefixes) != len(set(prefixes)) or any(item in _DEFAULTS for item in prefixes):
        raise WorkspaceScanError("INVALID_ALLOWLIST")
    combined = _DEFAULTS + prefixes
    for index, left in enumerate(combined):
        for right in combined[index + 1:]:
            if left.startswith(right + "/") or right.startswith(left + "/"):
                raise WorkspaceScanError("OVERLAPPING_ALLOWLIST")
    return prefixes


def _entry_paths(entry: Any) -> list[str] | None:
    if not isinstance(entry, str) or len(entry) < 4 or entry[2] != " ":
        return None
    status = entry[:2]
    if status not in {"??", "!!"} and (
        status == "  "
        or status[0] not in {" ", "M", "A", "D", "R", "C", "U", "T"}
        or status[1] not in {" ", "M", "D", "R", "C", "U", "T"}
    ):
        return None
    payload = entry[3:]
    has_endpoints = " -> " in payload
    if has_endpoints != any(character in {"R", "C"} for character in status):
        return None
    if status in {"??", "!!"} and payload.endswith("/") and not payload.endswith("//"):
        payload = payload[:-1]
    paths = payload.split(" -> ") if has_endpoints else [payload]
    if len(paths) not in {1, 2} or not all(_relative(path) for path in paths):
        return None
    return paths


def classify_workspace_entries(entries: Any, *, additional_allowed_prefixes=()) -> dict[str, Any]:
    """Partition status evidence without hiding allowed runtime residue."""
    if not isinstance(entries, (list, tuple)):
        raise WorkspaceScanError("INVALID_ENTRIES")
    configured = _validate_prefixes(additional_allowed_prefixes)
    allowed = _DEFAULTS + configured
    residue: list[dict[str, str]] = []
    product: list[dict[str, str]] = []
    rejected: list[dict[str, str]] = []
    for entry in entries:
        paths = _entry_paths(entry)
        if paths is None:
            rejected.append({"raw": entry if isinstance(entry, str) else repr(entry), "reason": "INVALID_ENTRY"})
            continue
        item = {"raw": entry, "path": paths[-1], "paths": paths}
        if all(
            any(path == prefix or path.startswith(prefix + "/") for prefix in allowed)
            for path in paths
        ):
            residue.append(item)
        else:
            product.append(item)
    return {
        "schema_version": "rerg-workspace-scan/v1",
        "default_allowed_prefixes": list(_DEFAULTS),
        "additional_allowed_prefixes": list(configured),
        "allowed_runtime_residue": residue,
        "product_dirt": product,
        "rejected_entries": rejected,
    }
