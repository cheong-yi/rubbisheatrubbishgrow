"""Bounded, inert target-repository evidence collection."""

from __future__ import annotations

import copy
from datetime import datetime
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any

from .git_worktree_inventory import (
    GitInventoryError,
    collect_git_worktree_inventory,
)
from .source_parser import parse_source_facts

_ADAPTER_ID = "rerg-repository-target-adapter"
_ADAPTER_VERSION = "1"
_MAX_PRE_STAT_CANDIDATES = 8
_MAX_INITIAL_READ_BYTES = 4 * 1024 * 1024
_MAX_DEPENDENCY_FILES = 8
_MAX_DEPENDENCY_DEPTH = 1
_MAX_DEPENDENCY_FILE_BYTES = 1_048_576
_MAX_DEPENDENCY_TOTAL_BYTES = 4_194_304
_MAX_SYMBOLS = 128
_MAX_IMPORTS = 128
_MAX_LITERAL_TOKENS = 64
_RUNTIME_COMPONENTS = {
    ".cache", ".git", ".gjc", ".mypy_cache", ".omx", ".pytest_cache",
    ".ruff_cache", ".tox", ".venv", "__pycache__", "node_modules", "venv",
}
_GENERATED_COMPONENTS = {"build", "dist", "coverage", "generated"}
_GENERIC_TOKENS = {
    "a", "an", "and", "are", "be", "for", "from", "in", "is", "it",
    "of", "on", "or", "safe", "source", "the", "to", "what", "which",
}
_TOKEN = re.compile(r"[a-z0-9]+")
_LOCATOR = re.compile(r"\b(?:https?|repository)://\S+", re.IGNORECASE)
_SENSITIVE_TOKENS = {
    "certificate", "certificates", "credential", "credentials", "key", "keys",
    "private", "secret", "secrets",
}
_SENSITIVE_EXACT_STEMS = {
    "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa",
}


class _BoundRoot:
    """Descriptor anchor for ordinary source reads.

    The anchor catches observable root/path replacement and every source body is
    opened relative to it. Git inventory remains path-based by design, so a
    malicious swap-and-restore of the whole worktree between identical Git state
    passes is residual risk rather than an in-scope blocker.
    """

    def __init__(self, path: Path, fd: int, identity: tuple[int, int, int]) -> None:
        self.path = path
        self.fd = fd
        self.identity = identity
        self.closed = False

    def close(self) -> None:
        if not self.closed:
            try:
                os.close(self.fd)
            except OSError:
                raise ValueError("SOURCE_CLEANUP_FAILED") from None
            self.closed = True


def _close_descriptors(descriptors: list[int]) -> bool:
    cleanup_failed = False
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError:
            cleanup_failed = True
    return cleanup_failed


def _directory_identity(value: os.stat_result) -> tuple[int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode)


def _open_bound_root(target_repository_root: str | Path | None) -> _BoundRoot:
    try:
        supplied = Path(target_repository_root)
    except TypeError:
        raise ValueError("NO_LOCAL_SOURCE_ROOT") from None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        fd = os.open(supplied, flags)
    except OSError:
        raise ValueError("NO_LOCAL_SOURCE_ROOT") from None
    try:
        opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode):
            raise ValueError("NO_LOCAL_SOURCE_ROOT")
        resolved = supplied.resolve(strict=True)
        handle = _BoundRoot(resolved, fd, _directory_identity(opened))
        _verify_bound_root(handle)
    except (OSError, ValueError):
        _close_descriptors([fd])
        raise ValueError("NO_LOCAL_SOURCE_ROOT") from None
    return handle


def _verify_bound_root(root: _BoundRoot) -> None:
    try:
        current = os.stat(root.path, follow_symlinks=False)
    except OSError:
        raise ValueError("SOURCE_CHANGED") from None
    if (
        not stat.S_ISDIR(current.st_mode)
        or _directory_identity(current) != root.identity
    ):
        raise ValueError("SOURCE_CHANGED")


def _path_lexical_score(relative: str, tokens: list[str]) -> tuple[int, list[str]]:
    """Score each lexical token at most once per path component."""
    token_set = set(tokens)
    matched: list[str] = []
    score = 0
    for component in PurePosixPath(relative).parts:
        component_terms = set(_TOKEN.findall(component.lower()))
        matches = sorted(token_set & component_terms)
        score += len(matches)
        matched.extend(matches)
    return score, sorted(set(matched))


def _rank_paths(paths: list[str], tokens: list[str]) -> list[dict[str, Any]]:
    """Select paths by deterministic lexical concept diversity."""
    eligible = []
    for relative in paths:
        score, matched = _path_lexical_score(relative, tokens)
        if score:
            eligible.append({
                "relative_posix_path": relative,
                "path_score": score,
                "matched_concepts": matched,
                "parser_supported": PurePosixPath(relative).suffix in {
                    ".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts",
                    ".tsx",
                },
            })
    selected: list[dict[str, Any]] = []
    covered: set[str] = set()
    while eligible and len(selected) < _MAX_PRE_STAT_CANDIDATES:
        additions = [
            (len(set(item["matched_concepts"]) - covered), item)
            for item in eligible
        ]
        if any(marginal > 0 for marginal, _ in additions):
            marginal, chosen = min(
                additions,
                key=lambda pair: (
                    -pair[0],
                    -int(pair[1]["parser_supported"]),
                    -pair[1]["path_score"],
                    pair[1]["relative_posix_path"],
                ),
            )
        else:
            chosen = min(
                eligible,
                key=lambda item: (
                    -int(item["parser_supported"]),
                    -item["path_score"],
                    item["relative_posix_path"],
                ),
            )
            marginal = 0
        selected.append({
            **chosen,
            "marginal_at_selection": marginal,
            "rank": len(selected) + 1,
        })
        covered.update(chosen["matched_concepts"])
        eligible.remove(chosen)
    return selected


def _empty_receipt(target: str, now: str, unknown: str) -> dict[str, Any]:
    return {
        "adapter_id": _ADAPTER_ID,
        "adapter_version": _ADAPTER_VERSION,
        "evidence_class": "implementation_source",
        "source_binding": None,
        "inventory": None,
        "target": target,
        "captured_at": now,
        "freshness": "current",
        "sources": [],
        "path_ranking": {
            "normalized_tokens": [],
            "inventory_records": 0,
            "max_pre_stat_candidates": _MAX_PRE_STAT_CANDIDATES,
            "max_initial_read_bytes": _MAX_INITIAL_READ_BYTES,
            "phase1_candidates": [],
        },
        "dependencies": {
            "observed": [], "inferred": [], "unknowns": [],
            "limits": {
                "max_dependency_files": _MAX_DEPENDENCY_FILES,
                "max_depth": _MAX_DEPENDENCY_DEPTH,
                "max_file_bytes": _MAX_DEPENDENCY_FILE_BYTES,
                "max_total_bytes": _MAX_DEPENDENCY_TOTAL_BYTES,
            },
        },
        "exclusions": [],
        "enumeration_truncated": False,
        "uninspected_surfaces": [],
        "unknowns": [unknown],
        "limitations": [unknown],
        "candidates": [],
    }


def _validated_context(
    context: Any, target_repository_root: str | Path | None,
) -> tuple[str, list[dict[str, str]]]:
    fields = {"target", "load_bearing_needs"}
    if not isinstance(context, dict) or set(context) not in (fields, fields | {"target_repository_root"}):
        raise ValueError("TARGET_CONTEXT_SHAPE")
    if "target_repository_root" in context:
        try:
            context_root = Path(context["target_repository_root"])
            supplied_root = Path(target_repository_root)
        except TypeError:
            raise ValueError("TARGET_CONTEXT_BINDING") from None
        if context_root != supplied_root:
            raise ValueError("TARGET_CONTEXT_BINDING")
    target = context.get("target")
    needs = context.get("load_bearing_needs")
    if not isinstance(target, str) or not target or not isinstance(needs, list):
        raise ValueError("TARGET_CONTEXT_SHAPE")
    if any(
        not isinstance(item, dict)
        or set(item) != {"need_id", "statement"}
        or not isinstance(item["need_id"], str) or not item["need_id"]
        or not isinstance(item["statement"], str) or not item["statement"].strip()
        for item in needs
    ):
        raise ValueError("TARGET_CONTEXT_SHAPE")
    return target, needs


def _exclusion(relative: str, name: str) -> str | None:
    """Classify one path component without substring matching.

    Sensitive components are ``.env*``; known private-key stems; certificate
    file extensions; or dot, underscore, and hyphen-delimited exact sensitive
    tokens. Thus ``private-key`` is excluded while ``keyboard`` is not.
    """
    lowered = name.lower()
    stem = lowered.rsplit(".", 1)[0]
    component_terms = set(re.findall(r"[a-z0-9]+", lowered))
    if lowered in _RUNTIME_COMPONENTS:
        return "runtime"
    if (
        lowered in _GENERATED_COMPONENTS
        or stem in _GENERATED_COMPONENTS
        or lowered.endswith((".pyc", ".pyo"))
    ):
        return "generated"
    if lowered == ".gitignore" or lowered.endswith("ignore"):
        return "ignore_rules"
    if (
        lowered.startswith(".env")
        or stem in _SENSITIVE_EXACT_STEMS
        or bool(component_terms & _SENSITIVE_TOKENS)
        or lowered.endswith((".key", ".pem", ".p12", ".pfx", ".crt", ".cer"))
    ):
        return "sensitive"
    return None


def _safe_relative(relative: str) -> bool:
    try:
        relative.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return (
        bool(relative)
        and "\x00" not in relative
        and "\\" not in relative
        and not relative.startswith(("/", "~"))
        and PurePosixPath(relative).as_posix() == relative
        and all(part not in {".", ".."} for part in PurePosixPath(relative).parts)
    )

def _coerce_bound_root(root: Path | _BoundRoot) -> tuple[_BoundRoot, bool]:
    if isinstance(root, _BoundRoot):
        _verify_bound_root(root)
        return root, False
    return _open_bound_root(root), True


def _stat_regular_source(root: Path | _BoundRoot, relative: str) -> tuple[int, int, int, int]:
    if not _safe_relative(relative):
        raise ValueError("SOURCE_ESCAPE")
    relative_parts = PurePosixPath(relative).parts
    if any(
        _exclusion(relative, component) is not None
        for component in relative_parts
    ):
        raise ValueError("SENSITIVE_SURFACE_EXCLUDED")
    handle, owned = _coerce_bound_root(root)
    current_fd = handle.fd if owned else os.dup(handle.fd)
    opened = [current_fd]
    try:
        for component in relative_parts[:-1]:
            component_before = os.stat(
                component, dir_fd=current_fd, follow_symlinks=False,
            )
            if not stat.S_ISDIR(component_before.st_mode):
                raise ValueError("SOURCE_ESCAPE")
            current_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current_fd,
            )
            opened.append(current_fd)
            component_opened = os.fstat(current_fd)
            if (
                component_before.st_dev,
                component_before.st_ino,
                component_before.st_mode,
            ) != (
                component_opened.st_dev,
                component_opened.st_ino,
                component_opened.st_mode,
            ):
                raise ValueError("SOURCE_CHANGED")
        final = os.stat(
            relative_parts[-1], dir_fd=current_fd, follow_symlinks=False,
        )
        if stat.S_ISLNK(final.st_mode):
            raise ValueError("SOURCE_ESCAPE")
        if not stat.S_ISREG(final.st_mode):
            raise ValueError("NOT_REGULAR_FILE")
        return (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
    finally:
        cleanup_failed = _close_descriptors(opened)
        if owned:
            handle.closed = True
        if cleanup_failed and sys.exc_info()[0] is None:
            raise ValueError("SOURCE_CLEANUP_FAILED")


def _read_regular_source(
    root: Path | _BoundRoot, relative: str, byte_budget: int,
) -> dict[str, Any]:
    if not _safe_relative(relative):
        raise ValueError("SOURCE_ESCAPE")
    relative_parts = PurePosixPath(relative).parts
    if any(
        _exclusion(relative, component) is not None
        for component in relative_parts
    ):
        raise ValueError("SENSITIVE_SURFACE_EXCLUDED")
    handle, owned = _coerce_bound_root(root)
    current_fd = handle.fd if owned else os.dup(handle.fd)
    opened: list[int] = [current_fd]
    try:
        for component in relative_parts[:-1]:
            component_before = os.stat(
                component, dir_fd=current_fd, follow_symlinks=False,
            )
            if not stat.S_ISDIR(component_before.st_mode):
                raise ValueError("SOURCE_ESCAPE")
            current_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current_fd,
            )
            opened.append(current_fd)
            component_opened = os.fstat(current_fd)
            if (
                component_before.st_dev,
                component_before.st_ino,
                component_before.st_mode,
            ) != (
                component_opened.st_dev,
                component_opened.st_ino,
                component_opened.st_mode,
            ):
                raise ValueError("SOURCE_CHANGED")
        before = os.stat(
            relative_parts[-1], dir_fd=current_fd, follow_symlinks=False,
        )
        if stat.S_ISLNK(before.st_mode):
            raise ValueError("SOURCE_ESCAPE")
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("NOT_REGULAR_FILE")
        if before.st_size > byte_budget:
            raise ValueError("INITIAL_READ_BYTE_LIMIT")
        # O_NONBLOCK plus the post-open fstat prevents blocking FIFO reads and
        # rejects non-regular replacements. It is not a blanket promise about
        # every device driver's open behavior; Git inventory admits only
        # ordinary regular-file worktree entries before this source read.
        file_fd = os.open(
            relative_parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=current_fd,
        )
        opened.append(file_fd)
        descriptor_before = os.fstat(file_fd)
        if not stat.S_ISREG(descriptor_before.st_mode):
            raise ValueError("NOT_REGULAR_FILE")
        if descriptor_before.st_size > byte_budget:
            raise ValueError("INITIAL_READ_BYTE_LIMIT")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(file_fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        descriptor_after = os.fstat(file_fd)
        path_after = os.stat(
            relative_parts[-1], dir_fd=current_fd, follow_symlinks=False,
        )
    finally:
        cleanup_failed = _close_descriptors(opened)
        if owned:
            handle.closed = True
        if cleanup_failed and sys.exc_info()[0] is None:
            raise ValueError("SOURCE_CLEANUP_FAILED")
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
    )
    if (
        identity(before) != identity(descriptor_before)
        or identity(before) != identity(descriptor_after)
        or identity(before) != identity(path_after)
        or len(data) != before.st_size
    ):
        raise ValueError("SOURCE_CHANGED")
    return {
        "data": data,
        "resolved": handle.path / relative,
        "identity": identity(before),
    }


def _source_passage_failure(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return "SOURCE_ENCODING"
    if not text:
        return "EMPTY_SOURCE_PASSAGE"
    if any(ord(char) < 32 and char not in "\t\n\r" for char in text):
        return "UNSAFE_SOURCE_PASSAGE"
    # Heuristic rejection, not proof that an admitted passage is secret-free.
    if re.search(
        r"(?i)(?:-----BEGIN [^\n]*PRIVATE KEY-----|"
        r"\b[a-z][a-z0-9+.-]*://[^\s/:@'\"?#]*:[^\s/@'\"?#]+@|"
        r"(?:api[_-]?key|password|secret|access[_-]?token)"
        r"\s*[:=]\s*['\"][^'\"]+['\"]|"
        r"\b(?:github[_-]?token|aws[_-](?:(?:secret[_-])?access[_-]key(?:[_-]id)?|session[_-]token))"
        r"\b['\"]?\s*[:=]\s*(?:['\"][^'\"]+['\"]|"
        r"[a-z0-9_./+~=-]+(?=\s|[,;}\]]|$))|"
        r"\bauthorization\b['\"]?\s*\]?\s*[:=]\s*['\"]?bearer\s+[^\s'\"]+|"
        r"\beyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+\b|"
        r"/(?:home|Users)/)",
        text,
    ):
        return "UNSAFE_SOURCE_PASSAGE"
    return None


def _source_facts(relative: str, data: bytes) -> dict[str, Any]:
    facts = parse_source_facts(relative, data)
    if (
        not isinstance(facts, dict)
        or set(facts) != {
            "language", "status", "symbols", "imports",
            "literal_tokens", "unknowns",
        }
        or not isinstance(facts["language"], str)
        or not isinstance(facts["status"], str)
        or not all(
            isinstance(facts[field], list)
            and all(isinstance(item, str) and item for item in facts[field])
            for field in ("symbols", "imports", "literal_tokens", "unknowns")
        )
    ):
        return {
            "language": "unsupported",
            "status": "PARSER_UNAVAILABLE:unknown",
            "symbols": [],
            "imports": [],
            "literal_tokens": [],
            "unknowns": ["PARSER_UNAVAILABLE:unknown"],
        }
    if _source_passage_failure(data) == "UNSAFE_SOURCE_PASSAGE":
        # Keep the parser outcome and byte/path binding, never content facts
        # that could also escape through dependency discovery or unknowns.
        return {
            "language": facts["language"],
            "status": facts["status"],
            "symbols": [],
            "imports": [],
            "literal_tokens": [],
            "unknowns": [] if facts["status"] == "PARSED" else [facts["status"]],
        }
    return {
        "language": facts["language"],
        "status": facts["status"],
        "symbols": list(dict.fromkeys(facts["symbols"]))[:_MAX_SYMBOLS],
        "imports": list(dict.fromkeys(facts["imports"]))[:_MAX_IMPORTS],
        "literal_tokens": list(dict.fromkeys(facts["literal_tokens"]))[
            :_MAX_LITERAL_TOKENS
        ],
        "unknowns": list(dict.fromkeys(facts["unknowns"]))[:_MAX_IMPORTS],
    }


def _dependency_exclusion(relative: str) -> bool:
    return any(
        _exclusion(relative, component) is not None
        for component in PurePosixPath(relative).parts
    )


def _supported_source_suffixes(language: str) -> list[str]:
    if language in {"typescript", "tsx"}:
        return [".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs"]
    return [".js", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]


def _specifier_base(source_path: str, specifier: str) -> str | None:
    if not specifier.startswith(("./", "../")):
        return None
    source_parent = PurePosixPath(source_path).parent
    parts = [] if str(source_parent) == "." else list(source_parent.parts)
    for part in PurePosixPath(specifier).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
            continue
        parts.append(part)
    if not parts:
        return None
    candidate = PurePosixPath(*parts).as_posix()
    return candidate if _safe_relative(candidate) else None


def _resolve_local_reference(
    *, root: _BoundRoot, source_path: str, language: str, specifier: str,
) -> tuple[str | None, str | None]:
    base = _specifier_base(source_path, specifier)
    if base is None:
        return None, "LOCAL_REFERENCE_ESCAPE"
    suffixes = _supported_source_suffixes(language)
    suffix = PurePosixPath(base).suffix
    if suffix:
        if suffix not in suffixes:
            return None, "UNSUPPORTED_LOCAL_REFERENCE"
        candidates = [base]
    else:
        candidates = [
            *(base + suffix for suffix in suffixes),
            *(base + "/index" + suffix for suffix in suffixes),
        ]
    available: list[str] = []
    excluded = False
    for candidate in candidates:
        if _dependency_exclusion(candidate):
            excluded = True
            continue
        try:
            _stat_regular_source(root, candidate)
        except (OSError, ValueError):
            continue
        available.append(candidate)
    if len(available) > 1:
        return None, "AMBIGUOUS_LOCAL_REFERENCE"
    if not available:
        return None, "EXCLUDED_DEPENDENCY" if excluded else "UNRESOLVED_LOCAL_REFERENCE"
    return available[0], None


def _discover_dependencies(
    *, root: _BoundRoot, seed_facts: list[dict[str, Any]], need_ids: list[str],
    captured_sources: dict[str, bytes], captured_identities: dict | None = None,
) -> dict[str, Any]:
    """Read at most one hop of source-local static references."""
    limits = {
        "max_dependency_files": _MAX_DEPENDENCY_FILES,
        "max_depth": _MAX_DEPENDENCY_DEPTH,
        "max_file_bytes": _MAX_DEPENDENCY_FILE_BYTES,
        "max_total_bytes": _MAX_DEPENDENCY_TOTAL_BYTES,
    }
    observed: list[dict[str, Any]] = []
    inferred: list[dict[str, Any]] = []
    unknowns: list[dict[str, Any]] = []
    read_cache: dict[str, bytes] = {
        item["relative_posix_path"]: item["data"]
        for item in seed_facts
    }
    total_bytes = 0
    dependency_files = 0

    def unknown(reason: str, **facts: Any) -> None:
        unknowns.append({"reason": reason, **facts, "need_ids": need_ids})

    def read_dependency(source_path: str, specifier: str, relative: str) -> bytes | None:
        nonlocal dependency_files, total_bytes
        if relative in read_cache:
            return read_cache[relative]
        if _dependency_exclusion(relative):
            unknown("EXCLUDED_DEPENDENCY", path=source_path, module=specifier)
            return None
        if dependency_files >= _MAX_DEPENDENCY_FILES:
            unknown("FILE_LIMIT", path=source_path, module=specifier)
            return None
        remaining = _MAX_DEPENDENCY_TOTAL_BYTES - total_bytes
        if remaining <= 0:
            unknown("BYTE_LIMIT", path=source_path, module=specifier)
            return None
        try:
            result = _read_regular_source(
                root, relative, min(_MAX_DEPENDENCY_FILE_BYTES, remaining)
            )
        except ValueError as error:
            reason = str(error)
            if reason == "INITIAL_READ_BYTE_LIMIT":
                unknown("BYTE_LIMIT", path=source_path, module=specifier)
            elif reason == "SENSITIVE_SURFACE_EXCLUDED":
                unknown("EXCLUDED_DEPENDENCY", path=source_path, module=specifier)
            elif reason == "SOURCE_CLEANUP_FAILED":
                unknown("SOURCE_CLEANUP_FAILED", path=source_path, module=specifier)
            else:
                unknown("SOURCE_CHANGED", path=source_path, module=specifier)
            return None
        except OSError:
            unknown("SOURCE_CHANGED", path=source_path, module=specifier)
            return None
        data = result["data"]
        total_bytes += len(data)
        dependency_files += 1
        read_cache[relative] = data
        captured_sources[relative] = data
        if captured_identities is not None:
            captured_identities[relative] = result["identity"]
        return data

    for item in seed_facts:
        relative = item["relative_posix_path"]
        data = item["data"]
        observed.append({
            "kind": "source",
            "path": relative,
            "sha256": hashlib.sha256(data).hexdigest(),
            "need_ids": need_ids,
        })
        for parser_unknown in item["facts"]["unknowns"]:
            unknown(parser_unknown, path=relative)
        if item["facts"]["status"] != "PARSED":
            continue
        for specifier in item["facts"]["imports"]:
            observed.append({
                "kind": "import",
                "path": relative,
                "module": specifier,
                "level": 0,
                "names": [],
                "need_ids": need_ids,
            })
            if not specifier.startswith(("./", "../")):
                continue
            resolved, failure = _resolve_local_reference(
                root=root, source_path=relative,
                language=item["facts"]["language"], specifier=specifier,
            )
            if resolved is None:
                unknown(failure or "UNRESOLVED_LOCAL_REFERENCE", path=relative, module=specifier)
                continue
            dependency_data = read_dependency(relative, specifier, resolved)
            if dependency_data is None:
                continue
            observed.append({
                "kind": "source",
                "path": resolved,
                "sha256": hashlib.sha256(dependency_data).hexdigest(),
                "need_ids": need_ids,
            })
            inferred.append({
                "source_path": relative,
                "dependency_path": resolved,
                "sha256": hashlib.sha256(dependency_data).hexdigest(),
                "need_ids": need_ids,
            })

    unique_observed = {
        (
            item["kind"], item.get("path"), item.get("module"),
            tuple(item.get("names", [])),
        ): item
        for item in observed
    }
    unique_inferred = {
        (item["source_path"], item["dependency_path"]): item
        for item in inferred
    }
    return {
        "observed": list(unique_observed.values()),
        "inferred": list(unique_inferred.values()),
        "unknowns": unknowns,
        "limits": limits,
    }

def adapt_repository_target(
    *, target_context: Any, target_repository_root: str | Path | None,
    question: str, now: str, followup: Any = None,
) -> dict[str, Any]:
    """Collect a bounded private receipt without interpreting or authorizing it."""
    target, needs = _validated_context(target_context, target_repository_root)
    if not isinstance(question, str) or not question.strip() or len(question) > 4096:
        raise ValueError("TARGET_QUESTION")
    try:
        timestamp = datetime.fromisoformat(now.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise ValueError("TARGET_CAPTURE_TIME") from None
    if timestamp.tzinfo is None:
        raise ValueError("TARGET_CAPTURE_TIME")
    if followup is not None:
        from .path_query import _validate_followup_request
        _validate_followup_request(
            followup, target=target, now=now,
            need_ids=[item["need_id"] for item in needs], question=question,
            statements=[item["statement"] for item in needs],
        )
    try:
        root = _open_bound_root(target_repository_root)
    except ValueError:
        return {
            "receipt": _empty_receipt(target, now, "NO_LOCAL_SOURCE_ROOT"),
            "passages": [], "failures": [],
        }
    captured_sources: dict[str, bytes] = {}
    captured_identities: dict = {}
    try:
        receipt = _adapt_bound_repository_target(
            target=target, needs=needs, root=root, question=question, now=now,
            captured_sources=captured_sources,
            captured_identities=captured_identities,
        )
        if followup is not None:
            _recapture_followup(root, receipt, captured_sources, captured_identities, followup)
    except BaseException:
        try:
            root.close()
        except ValueError:
            pass
        raise
    try:
        root.close()
    except ValueError:
        if receipt["source_binding"] is not None or receipt["sources"]:
            receipt = _empty_receipt(target, now, "SOURCE_CLEANUP_FAILED")
    return _captured_repository_passages(receipt, captured_sources)


def _recapture_followup(root, receipt, captured_sources, captured_identities, request):
    from .path_query import _FOLLOWUP_LIMITS, _followup_eligible_paths, _receipt_source_hashes

    prior = request["prior_receipt"]
    if receipt != {**prior, "captured_at": receipt["captured_at"]}:
        raise ValueError("FOLLOWUP_BINDING")
    # The freshly recaptured base must agree byte-for-byte, including dirty
    # sources whose porcelain status/inventory digest did not change.
    prior_hashes = _receipt_source_hashes(prior)
    if any(hashlib.sha256(captured_sources.get(path, b"")).hexdigest() != digest
           for path, digest in prior_hashes.items()):
        raise ValueError("FOLLOWUP_BINDING")
    section = {**copy.deepcopy(request), "limits": dict(_FOLLOWUP_LIMITS),
               "sources": [], "failures": [], "total_bytes": 0}
    eligible = _followup_eligible_paths(receipt)
    checks = {}
    stopped = False
    for path in request["paths"]:
        code, charged = None, 0
        remaining = _FOLLOWUP_LIMITS["max_total_bytes"] - section["total_bytes"]
        if path not in eligible:
            code = "FOLLOWUP_INELIGIBLE"
        elif stopped or not remaining:
            code = "FOLLOWUP_BYTE_LIMIT"
        else:
            try:
                read = _read_regular_source(root, path, remaining)
            except (OSError, ValueError) as error:
                # The reader may have consumed bytes before raising. Charge
                # the whole remaining allowance and never continue reads.
                charged, stopped = remaining, True
                code = "FOLLOWUP_SOURCE_CHANGED" if str(error) == "SOURCE_CHANGED" else "FOLLOWUP_READ_FAILED"
                if str(error) == "SOURCE_CLEANUP_FAILED":
                    raise ValueError("SOURCE_CLEANUP_FAILED") from None
            else:
                data = read["data"]
                charged = len(data)
                facts = _source_facts(path, data)
                source = {
                    "relative_posix_path": path, "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data), "regular_file": True, "confined": True, "race_checked": True,
                    "language": facts["language"], "status": facts["status"],
                    "symbols": facts["symbols"], "imports": facts["imports"],
                    "literal_tokens": facts["literal_tokens"], "parse_unknowns": facts["unknowns"],
                }
                screened = _captured_repository_passages(
                    {**receipt, "sources": [source], "dependencies": {"observed": []}}, {path: data},
                )
                if screened["failures"]:
                    code = "FOLLOWUP_" + screened["failures"][0]["code"]
                else:
                    section["sources"].append(source)
                    captured_sources[path] = data
                    checks[path] = read["identity"]
        section["total_bytes"] += charged
        if code:
            section["failures"].append({"path": path, "code": code, "bytes": charged})
    _verify_bound_root(root)
    if collect_git_worktree_inventory(root.path) != receipt["inventory"]:
        raise ValueError("FOLLOWUP_BINDING")
    _verify_bound_root(root)
    for path, identity in checks.items():
        try:
            unchanged = _stat_regular_source(root, path) == identity
        except (OSError, ValueError):
            unchanged = False
        if not unchanged:
            source = next(item for item in section["sources"] if item["relative_posix_path"] == path)
            section["sources"].remove(source)
            section["failures"].append({
                "path": path, "code": "FOLLOWUP_SOURCE_CHANGED", "bytes": source["bytes"],
            })
    # Verify the identities from the original recapture reads, without inventing
    # another byte budget. The documented swap-and-restore limitation still applies.
    for path in prior_hashes:
        if _stat_regular_source(root, path) != captured_identities.get(path):
            raise ValueError("FOLLOWUP_BINDING")
    _verify_bound_root(root)
    receipt["followup"] = section
    receipt["uninspected_surfaces"] = sorted(set(receipt["uninspected_surfaces"]) - {
        item["relative_posix_path"] for item in section["sources"]
    })


def _captured_repository_passages(
    receipt: dict[str, Any], captured_sources: dict[str, bytes],
) -> dict[str, Any]:
    """Project excerpts from admitted bytes only; never reopen a source."""
    passages: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    binding = receipt["source_binding"]
    if binding is None:
        return {"receipt": receipt, "passages": passages, "failures": failures}
    admitted = {
        source["relative_posix_path"]: source["sha256"]
        for source in receipt["sources"]
    }
    admitted.update({
        source["path"]: source["sha256"]
        for source in receipt["dependencies"]["observed"]
        if source["kind"] == "source"
    })
    followup = receipt.get("followup")
    if followup is not None:
        admitted.update({
            source["relative_posix_path"]: source["sha256"] for source in followup["sources"]
        })
        failures.extend({
            "code": failure["code"], "artifact_id": "target:" + failure["path"],
            "missing_fact": followup["missing_fact"],
            "decision_blocked": "Use of this additional source as implementation evidence.",
        } for failure in followup["failures"])
    pin = (
        f'{binding["head_oid"]}:{binding["inventory_sha256"]}:'
        f'{binding["scope_identity_sha256"]}'
    )
    for relative, digest in sorted(admitted.items()):
        artifact_id = "target:" + relative
        data = captured_sources.get(relative)
        code = None
        if data is None or hashlib.sha256(data).hexdigest() != digest:
            code = "SOURCE_CHANGED"
        else:
            code = _source_passage_failure(data)
        if code is not None:
            failures.append({
                "code": code,
                "artifact_id": artifact_id,
                "missing_fact": "A safe source excerpt is unavailable.",
                "decision_blocked": "Use of this source as implementation evidence.",
            })
            continue
        text = data.decode("utf-8")
        artifact = {
            "id": artifact_id,
            "role": "target",
            "locator": relative,
            "pin": pin,
            "captured_at": receipt["captured_at"],
            "source_sha256": digest,
            "representation": {
                "text": text,
                "sha256": digest,
                "sanitization": {
                    "method": "bounded-source-screen; host review required",
                    "redacted": False,
                },
                "truncated": False,
            },
            "citations": [{
                "id": artifact_id + ":body",
                "artifact_id": artifact_id,
                "representation_sha256": digest,
                "start_byte": 0,
                "end_byte": len(data),
                "quote": text,
            }],
        }
        passages.append({
            "artifact": artifact, "source_path": relative,
            "source_sha256": digest,
        })
    return {"receipt": receipt, "passages": passages, "failures": failures}


def _adapt_bound_repository_target(
    *, target: str, needs: list[dict[str, str]], root: _BoundRoot,
    question: str, now: str,
    captured_sources: dict[str, bytes], captured_identities: dict | None = None,
) -> dict[str, Any]:
    raw_tokens = _TOKEN.findall(" ".join([
        _LOCATOR.sub(" ", question), *(item["statement"] for item in needs)
    ]).lower())
    tokens = [
        token for token in dict.fromkeys(raw_tokens)
        if token not in _GENERIC_TOKENS
    ][:_MAX_SYMBOLS // 2]
    try:
        _verify_bound_root(root)
        inventory = collect_git_worktree_inventory(root.path)
        _verify_bound_root(root)
    except GitInventoryError as error:
        return _empty_receipt(target, now, str(error))
    except (OSError, ValueError):
        return _empty_receipt(target, now, "SOURCE_CHANGED")
    exclusions = [
        {
            "category": item["category"],
            "relative_posix_path": item["path"],
        }
        for item in inventory["exclusions"]
    ]
    paths: list[str] = []
    unavailable: list[str] = []
    for record in inventory["records"]:
        relative = record["path"]
        category = None
        exclusion_path = relative
        components: list[str] = []
        for component in PurePosixPath(relative).parts:
            components.append(component)
            category = _exclusion(relative, component)
            if category is not None:
                exclusion_path = PurePosixPath(*components).as_posix()
                break
        if category is not None:
            exclusions.append({
                "category": category,
                "relative_posix_path": exclusion_path,
            })
        elif record["availability"] == "available":
            paths.append(relative)
        else:
            unavailable.append(relative)
    exclusions = sorted(
        {
            item["relative_posix_path"]: item
            for item in exclusions
        }.values(),
        key=lambda item: item["relative_posix_path"],
    )
    ranked = _rank_paths(paths, tokens)
    selected_phase1_paths = {
        item["relative_posix_path"] for item in ranked
    }
    uninspected = unavailable + [
        path for path in paths if path not in selected_phase1_paths
    ]
    uninspected = sorted(set(uninspected))
    unknowns: list[str] = []
    if any(item["category"] == "sensitive" for item in exclusions):
        unknowns.append("SENSITIVE_SURFACE_EXCLUDED")
    if unavailable:
        unknowns.append("UNAVAILABLE_SURFACE")
    if inventory["worktree_state"] == "dirty":
        unknowns.append("DIRTY_IMPLEMENTATION_SOURCE")

    sources: list[dict[str, Any]] = []
    source_checks: dict[str, dict[str, Any]] = {}
    initial_bytes = 0
    source_changed = False
    for ranking in ranked:
        relative = ranking["relative_posix_path"]
        try:
            read = _read_regular_source(
                root, relative, _MAX_INITIAL_READ_BYTES - initial_bytes
            )
        except ValueError as error:
            reason = str(error)
            if reason not in {
                "NOT_REGULAR_FILE", "INITIAL_READ_BYTE_LIMIT", "SOURCE_CHANGED",
                "SENSITIVE_SURFACE_EXCLUDED", "SOURCE_CLEANUP_FAILED",
            }:
                reason = "SOURCE_ESCAPE"
            unknowns.append(reason)
            source_changed |= reason == "SOURCE_CHANGED"
            uninspected.append(relative)
            continue
        except OSError:
            unknowns.append("SOURCE_ESCAPE")
            uninspected.append(relative)
            continue
        data = read["data"]
        facts = _source_facts(relative, data)
        try:
            final_identity = _stat_regular_source(root, relative)
        except (OSError, ValueError):
            unknowns.append("SOURCE_CHANGED")
            source_changed = True
            uninspected.append(relative)
            continue
        if final_identity != read["identity"]:
            unknowns.append("SOURCE_CHANGED")
            source_changed = True
            uninspected.append(relative)
            continue
        initial_bytes += len(data)
        sources.append({
            "relative_posix_path": relative,
            "sha256": hashlib.sha256(data).hexdigest(),
            "regular_file": True,
            "confined": True,
            "race_checked": True,
            "path_score": ranking["path_score"],
            "matched_concepts": ranking["matched_concepts"],
            "language": facts["language"],
            "status": facts["status"],
            "symbols": facts["symbols"],
            "imports": facts["imports"],
            "literal_tokens": facts["literal_tokens"],
            "parse_unknowns": facts["unknowns"],
        })
        source_checks[relative] = {**read, "facts": facts}
        captured_sources[relative] = data
        if captured_identities is not None:
            captured_identities[relative] = read["identity"]
        unknowns.extend(facts["unknowns"])

    dependency_receipt = {
        "observed": [], "inferred": [], "unknowns": [],
        "limits": {
            "max_dependency_files": _MAX_DEPENDENCY_FILES,
            "max_depth": _MAX_DEPENDENCY_DEPTH,
            "max_file_bytes": _MAX_DEPENDENCY_FILE_BYTES,
            "max_total_bytes": _MAX_DEPENDENCY_TOTAL_BYTES,
        },
    }
    if sources and not source_changed:
        try:
            dependency_receipt = _discover_dependencies(
                root=root,
                seed_facts=[
                    {
                        "relative_posix_path": source["relative_posix_path"],
                        "data": source_checks[source["relative_posix_path"]]["data"],
                        "facts": source_checks[source["relative_posix_path"]]["facts"],
                    }
                    for source in sources
                ],
                need_ids=[item["need_id"] for item in needs],
                captured_sources=captured_sources,
                captured_identities=captured_identities,
            )
        except (OSError, ValueError):
            dependency_receipt["unknowns"].append({
                "reason": "DEPENDENCY_DISCOVERY_FAILED",
                "need_ids": [item["need_id"] for item in needs],
            })

    changed_paths: set[str] = set()
    discovery_digests = {
        item["path"]: item["sha256"]
        for item in dependency_receipt["observed"]
        if (
            isinstance(item, dict)
            and item.get("kind") == "source"
            and isinstance(item.get("path"), str)
            and isinstance(item.get("sha256"), str)
        )
    }
    for source in sources:
        relative = source["relative_posix_path"]
        check = source_checks[relative]
        try:
            final_identity = _stat_regular_source(root, relative)
        except (OSError, ValueError):
            changed_paths.add(relative)
            continue
        if (
            final_identity != check["identity"]
            or (
                relative in discovery_digests
                and discovery_digests[relative] != source["sha256"]
            )
        ):
            changed_paths.add(relative)
    if changed_paths:
        uninspected.extend(changed_paths)
        sources = [
            item for item in sources
            if item["relative_posix_path"] not in changed_paths
        ]
        dependency_receipt["observed"] = [
            item for item in dependency_receipt["observed"]
            if item.get("path") not in changed_paths
        ]
        dependency_receipt["inferred"] = [
            item for item in dependency_receipt["inferred"]
            if item.get("source_path") not in changed_paths
            and item.get("dependency_path") not in changed_paths
        ]
        dependency_receipt["unknowns"].append({
            "reason": "SOURCE_CHANGED",
            "need_ids": [item["need_id"] for item in needs],
        })
        unknowns.append("SOURCE_CHANGED")

    if not ranked or not sources:
        unknowns.append("INSUFFICIENT_RELEVANCE")
    if len(sources) > 1 and sources[0]["path_score"] == sources[1]["path_score"]:
        unknowns.append("AMBIGUOUS_RELEVANCE")
    if sources:
        unknowns.append("SEMANTIC_RELEVANCE_UNINTERPRETED")
    unknowns.extend(
        item["reason"] for item in dependency_receipt["unknowns"]
        if isinstance(item, dict) and isinstance(item.get("reason"), str)
    )
    unknowns = list(dict.fromkeys(unknowns))
    source_order = {
        item["relative_posix_path"]: index
        for index, item in enumerate(sources)
    }
    candidates = sorted((
        {
            "relative_posix_path": item["relative_posix_path"],
            "sha256": item["sha256"],
            "score": item["path_score"],
            "authorizing": False,
        }
        for item in sources
    ), key=lambda item: source_order[item["relative_posix_path"]])[:8]
    try:
        _verify_bound_root(root)
    except (OSError, ValueError):
        return _empty_receipt(target, now, "SOURCE_CHANGED")
    return {
        "adapter_id": _ADAPTER_ID,
        "adapter_version": _ADAPTER_VERSION,
        "evidence_class": "implementation_source",
        "source_binding": {
            "vcs": "git",
            "head_oid": inventory["head_oid"],
            "scope_identity_sha256": inventory["scope_identity_sha256"],
            "scope_prefix": inventory["scope_prefix"],
            "inventory_sha256": inventory["inventory_sha256"],
            "worktree_state": inventory["worktree_state"],
            "dirty_paths": inventory["dirty_paths"],
        },
        "inventory": inventory,
        "target": target,
        "captured_at": now,
        "freshness": "current",
        "sources": sources,
        "path_ranking": {
            "normalized_tokens": tokens,
            "inventory_records": len(inventory["records"]),
            "max_pre_stat_candidates": _MAX_PRE_STAT_CANDIDATES,
            "max_initial_read_bytes": _MAX_INITIAL_READ_BYTES,
            "phase1_candidates": ranked,
        },
        "dependencies": dependency_receipt,
        "exclusions": exclusions,
        "enumeration_truncated": False,
        "uninspected_surfaces": sorted(set(uninspected)),
        "unknowns": unknowns,
        "limitations": list(unknowns),
        "candidates": candidates,
    }


__all__ = ["adapt_repository_target"]
