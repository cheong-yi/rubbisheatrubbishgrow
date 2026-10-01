"""Target-map binding for the raw, inert RERG lane."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any

class MapBindingError(ValueError):
    def __init__(self, *reasons: str) -> None:
        self.reasons = tuple(dict.fromkeys(reasons))
        super().__init__(";".join(self.reasons))


def _safe(path: Any) -> bool:
    if not isinstance(path, str) or not path:
        return False
    try:
        path.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return "\x00" not in path and "\\" not in path and not path.startswith(("/", "~")) and \
        all(part not in {".", ".."} for part in PurePosixPath(path).parts) and PurePosixPath(path).as_posix() == path


_RECEIPT_FIELDS = {
    "adapter_id", "adapter_version", "target", "captured_at", "freshness",
    "evidence_class", "source_binding", "inventory",
    "sources", "path_ranking", "dependencies", "exclusions",
    "enumeration_truncated", "uninspected_surfaces", "unknowns",
    "limitations", "candidates",
}
_SOURCE_FIELDS = {
    "relative_posix_path", "sha256", "regular_file", "confined",
    "race_checked", "path_score", "matched_concepts", "language", "status",
    "symbols", "imports", "literal_tokens", "parse_unknowns",
}
_DEPENDENCY_LIMITS = {
    "max_dependency_files": 8,
    "max_depth": 1,
    "max_file_bytes": 1_048_576,
    "max_total_bytes": 4_194_304,
}
_TOKEN = re.compile(r"[a-z0-9]+")
_LOCATOR = re.compile(r"\b(?:https?|repository)://\S+", re.IGNORECASE)
_GENERIC_TOKENS = {
    "a", "an", "and", "are", "be", "for", "from", "in", "is", "it",
    "of", "on", "or", "safe", "source", "the", "to", "what", "which",
}
_JS_SUFFIXES = {".js", ".mjs", ".cjs"}
_TS_SUFFIXES = {".ts", ".mts", ".cts"}
_TSX_SUFFIXES = {".tsx"}
_RUNTIME_COMPONENTS = {
    ".cache", ".git", ".gjc", ".mypy_cache", ".omx", ".pytest_cache",
    ".ruff_cache", ".tox", ".venv", "__pycache__", "node_modules", "venv",
}
_GENERATED_COMPONENTS = {"build", "dist", "coverage", "generated"}
_SENSITIVE_TOKENS = {
    "certificate", "certificates", "credential", "credentials", "key", "keys",
    "private", "secret", "secrets",
}
_SENSITIVE_EXACT_STEMS = {
    "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa",
}
_FOLLOWUP_LIMITS = {"max_files": 4, "max_total_bytes": 1_048_576, "max_rounds": 1}


def _followup_eligible_paths(receipt: dict) -> set[str]:
    excluded = {item["relative_posix_path"] for item in receipt["exclusions"]}
    return {
        item["path"] for item in receipt["inventory"]["records"]
        if item["availability"] == "available"
        and not _is_excluded(item["path"], excluded)
        and _source_exclusion(item["path"]) is None
        and not {part.lower() for part in PurePosixPath(item["path"]).parts}
        & {"eval", "evaluation", "evaluations"}
    }


def _receipt_source_hashes(receipt: dict) -> dict[str, str]:
    result = {item["relative_posix_path"]: item["sha256"] for item in receipt["sources"]}
    result.update({
        item["path"]: item["sha256"] for item in receipt["dependencies"]["observed"]
        if item["kind"] == "source"
    })
    return result


def _validate_followup_request(request: Any, *, target, now, need_ids, question, statements):
    from .raw_derivation import _text
    from .raw_intake import _adoption_time

    if type(request) is not dict or set(request) != {"prior_receipt", "missing_fact", "need_ids", "paths"}:
        raise MapBindingError("FOLLOWUP_SHAPE")
    prior = request["prior_receipt"]
    if type(prior) is not dict or "followup" in prior:
        raise MapBindingError("FOLLOWUP_LINEAGE")
    _validate_adapter_receipt(
        prior, target=target, now=prior.get("captured_at"), need_ids=need_ids,
        question=question, statements=statements,
    )
    if prior["source_binding"] is None or _adoption_time(prior["captured_at"]) > _adoption_time(now):
        raise MapBindingError("FOLLOWUP_BINDING")
    _text(request["missing_fact"])
    if not request["missing_fact"].strip() or len(request["missing_fact"]) > 4096:
        raise MapBindingError("FOLLOWUP_SHAPE")
    ids = request["need_ids"]
    paths = request["paths"]
    if (not _string_list(ids) or not ids or len(ids) != len(set(ids))
            or not set(ids) <= set(need_ids)):
        raise MapBindingError("FOLLOWUP_NEEDS")
    if (not _string_list(paths) or len(paths) > 4 or len(paths) != len(set(paths))
            or any(not _safe(path) or len(path.encode("utf-8")) > 4096
                   or any(ord(char) < 32 for char in path) for path in paths)):
        raise MapBindingError("FOLLOWUP_PATHS")
    if set(paths) & set(_receipt_source_hashes(prior)):
        raise MapBindingError("FOLLOWUP_ALREADY_ADMITTED")


def _validate_followup_receipt(receipt, *, target, now, need_ids, question, statements):
    if set(receipt) != _RECEIPT_FIELDS | {"followup"}:
        raise MapBindingError("MAP_BINDING")
    section = receipt["followup"]
    request_fields = {"prior_receipt", "missing_fact", "need_ids", "paths"}
    if type(section) is not dict or set(section) != request_fields | {
        "limits", "sources", "failures", "total_bytes",
    }:
        raise MapBindingError("FOLLOWUP_SHAPE")
    request = {key: section[key] for key in request_fields}
    _validate_followup_request(request, target=target, now=now, need_ids=need_ids,
                               question=question, statements=statements)
    sources, failures = section["sources"], section["failures"]
    if (section["limits"] != _FOLLOWUP_LIMITS
            or any(type(value) is not int for value in section["limits"].values())
            or type(sources) is not list
            or type(failures) is not list or len(sources) + len(failures) != len(section["paths"])
            or type(section["total_bytes"]) is not int
            or not 0 <= section["total_bytes"] <= _FOLLOWUP_LIMITS["max_total_bytes"]):
        raise MapBindingError("FOLLOWUP_LIMIT")
    prior = section["prior_receipt"]
    eligible = _followup_eligible_paths(prior)
    source_fields = (_SOURCE_FIELDS - {"path_score", "matched_concepts"}) | {"bytes"}
    for source in sources:
        if (type(source) is not dict or set(source) != source_fields
                or source["relative_posix_path"] not in eligible
                or not _digest(source["sha256"])
                or any(source[key] is not True for key in ("regular_file", "confined", "race_checked"))
                or type(source["bytes"]) is not int or not 0 < source["bytes"] <= 1_048_576
                or any(not _string_list(source[key]) or len(source[key]) > maximum
                       for key, maximum in (("symbols", 128), ("imports", 128),
                                            ("literal_tokens", 64), ("parse_unknowns", 128)))
                or not isinstance(source["language"], str) or not isinstance(source["status"], str)
                or not _source_status_coherent(source)
                or (source["status"] != "PARSED" and any(source[key] for key in
                                                       ("symbols", "imports", "literal_tokens")))):
            raise MapBindingError("FOLLOWUP_SOURCE")
    failure_codes = {
        "FOLLOWUP_INELIGIBLE", "FOLLOWUP_READ_FAILED", "FOLLOWUP_BYTE_LIMIT",
        "FOLLOWUP_SOURCE_CHANGED", "FOLLOWUP_SOURCE_ENCODING", "FOLLOWUP_EMPTY_SOURCE_PASSAGE",
        "FOLLOWUP_UNSAFE_SOURCE_PASSAGE",
    }
    for failure in failures:
        if (type(failure) is not dict or set(failure) != {"path", "code", "bytes"}
                or type(failure["path"]) is not str or type(failure["code"]) is not str
                or failure["code"] not in failure_codes
                or type(failure["bytes"]) is not int or not 0 <= failure["bytes"] <= 1_048_576):
            raise MapBindingError("FOLLOWUP_FAILURE")
    paths = [source["relative_posix_path"] for source in sources] + [f["path"] for f in failures]
    if (len(set(paths)) != len(paths) or set(paths) != set(section["paths"])
            or sum(item["bytes"] for item in sources + failures) != section["total_bytes"]):
        raise MapBindingError("FOLLOWUP_ACCOUNTING")
    by_path = {item["relative_posix_path"]: item for item in sources}
    by_path.update({item["path"]: item for item in failures})
    remaining = _FOLLOWUP_LIMITS["max_total_bytes"]
    for path in section["paths"]:
        record = by_path[path]
        code = record.get("code")
        if (record["bytes"] > remaining
                or (code == "FOLLOWUP_INELIGIBLE" and (path in eligible or record["bytes"] != 0))
                or (code != "FOLLOWUP_INELIGIBLE" and path not in eligible)
                or (code == "FOLLOWUP_READ_FAILED" and (not remaining or record["bytes"] != remaining))
                or (code == "FOLLOWUP_BYTE_LIMIT" and (remaining != 0 or record["bytes"] != 0))):
            raise MapBindingError("FOLLOWUP_ACCOUNTING")
        remaining -= record["bytes"]
    base = {key: copy.deepcopy(value) for key, value in receipt.items() if key != "followup"}
    base["uninspected_surfaces"] = sorted(set(base["uninspected_surfaces"]) | {
        source["relative_posix_path"] for source in sources
    })
    _validate_adapter_receipt(base, target=target, now=now, need_ids=need_ids,
                              question=question, statements=statements)
    expected = {**prior, "captured_at": now}
    if base != expected or receipt["uninspected_surfaces"] != sorted(
        set(prior["uninspected_surfaces"]) - {source["relative_posix_path"] for source in sources}
    ):
        raise MapBindingError("FOLLOWUP_BINDING")


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _oid(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) in {40, 64}
        and all(character in "0123456789abcdef" for character in value)
    )


def _path_ranking_facts(path: str, tokens: list[str]) -> tuple[int, list[str]]:
    token_set = set(tokens)
    matched: list[str] = []
    score = 0
    for component in PurePosixPath(path).parts:
        matches = sorted(token_set & set(_TOKEN.findall(component.lower())))
        score += len(matches)
        matched.extend(matches)
    return score, sorted(set(matched))


def _normalized_concepts(question: str, statements: list[str]) -> list[str]:
    raw = _TOKEN.findall(" ".join([
        _LOCATOR.sub(" ", question), *statements,
    ]).lower())
    return [
        token for token in dict.fromkeys(raw)
        if token not in _GENERIC_TOKENS
    ][:64]


def _select_rankings(paths: list[str], tokens: list[str]) -> list[dict[str, Any]]:
    eligible = []
    for path in paths:
        score, matched = _path_ranking_facts(path, tokens)
        if score:
            eligible.append({
                "relative_posix_path": path,
                "path_score": score,
                "matched_concepts": matched,
                "parser_supported": PurePosixPath(path).suffix in {
                    ".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts",
                    ".tsx",
                },
            })
    selected = []
    covered: set[str] = set()
    while eligible and len(selected) < 8:
        additions = [
            (len(set(item["matched_concepts"]) - covered), item)
            for item in eligible
        ]
        if any(marginal for marginal, _ in additions):
            marginal, chosen = min(
                additions,
                key=lambda pair: (
                    -pair[0], -int(pair[1]["parser_supported"]),
                    -pair[1]["path_score"], pair[1]["relative_posix_path"],
                ),
            )
        else:
            chosen = min(
                eligible,
                key=lambda item: (
                    -int(item["parser_supported"]), -item["path_score"],
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


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()


def _language_for_path(path: str) -> str:
    suffix = PurePosixPath(path).suffix
    if suffix == ".py":
        return "python"
    if suffix in _JS_SUFFIXES:
        return "javascript"
    if suffix in _TS_SUFFIXES:
        return "typescript"
    if suffix in _TSX_SUFFIXES:
        return "tsx"
    return "unsupported"


def _source_status_coherent(item: dict[str, Any]) -> bool:
    language = item["language"]
    status = item["status"]
    unknowns = item["parse_unknowns"]
    if language != _language_for_path(item["relative_posix_path"]):
        return False
    if language == "unsupported":
        return status == "UNSUPPORTED_LANGUAGE" and unknowns == [status]
    if status == "PARSED":
        return not any(
            reason in unknowns
            for reason in (
                "SYNTAX_ERROR", "INVALID_SOURCE_ENCODING", "PARSER_RESOURCE_LIMIT",
                "UNSUPPORTED_LANGUAGE", f"PARSER_UNAVAILABLE:{language}",
                "SOURCE_ENCODING", "EMPTY_SOURCE_PASSAGE", "UNSAFE_SOURCE_PASSAGE",
                "FOLLOWUP_SOURCE_ENCODING", "FOLLOWUP_EMPTY_SOURCE_PASSAGE",
                "FOLLOWUP_UNSAFE_SOURCE_PASSAGE",
            )
        )
    if status in {"SYNTAX_ERROR", "INVALID_SOURCE_ENCODING", "PARSER_RESOURCE_LIMIT"}:
        return unknowns == [status]
    if status == f"PARSER_UNAVAILABLE:{language}":
        return unknowns == [status]
    return False


def _source_exclusion(path: str) -> tuple[str, str] | None:
    components = []
    for component in PurePosixPath(path).parts:
        components.append(component)
        lowered = component.lower()
        stem = lowered.rsplit(".", 1)[0]
        component_terms = set(_TOKEN.findall(lowered))
        category = None
        if lowered in _RUNTIME_COMPONENTS:
            category = "runtime"
        elif (
            lowered in _GENERATED_COMPONENTS
            or stem in _GENERATED_COMPONENTS
            or lowered.endswith((".pyc", ".pyo"))
        ):
            category = "generated"
        elif lowered == ".gitignore" or lowered.endswith("ignore"):
            category = "ignore_rules"
        elif (
            lowered.startswith(".env")
            or stem in _SENSITIVE_EXACT_STEMS
            or bool(component_terms & _SENSITIVE_TOKENS)
            or lowered.endswith((
                ".key", ".pem", ".p12", ".pfx", ".crt", ".cer",
            ))
        ):
            category = "sensitive"
        if category is not None:
            return category, PurePosixPath(*components).as_posix()
    return None


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
    return candidate if _safe(candidate) else None


def _is_excluded(path: str, excluded_paths: set[str]) -> bool:
    return any(
        path == excluded_path or path.startswith(excluded_path + "/")
        for excluded_path in excluded_paths
    )


def _resolve_local_reference_from_receipt(
    *,
    source_path: str,
    language: str,
    specifier: str,
    available_paths: set[str],
    excluded_paths: set[str],
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
    excluded = False
    available = []
    for candidate in candidates:
        if _is_excluded(candidate, excluded_paths):
            excluded = True
            continue
        if candidate in available_paths:
            available.append(candidate)
    if len(available) > 1:
        return None, "AMBIGUOUS_LOCAL_REFERENCE"
    if not available:
        return None, "EXCLUDED_DEPENDENCY" if excluded else "UNRESOLVED_LOCAL_REFERENCE"
    return available[0], None


def _dedupe_dependency_records(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    deduped: dict[tuple[Any, ...], dict[str, Any]] = {}
    for item in records:
        if item["kind"] == "source":
            key = ("source", item["path"])
        else:
            key = ("import", item["path"], item["module"], tuple(item["names"]))
        deduped[key] = item
    return list(deduped.values())


def _expected_dependency_receipt_subset(
    *,
    sources: list[dict[str, Any]],
    inventory_records: list[dict[str, Any]],
    exclusions: list[dict[str, Any]],
    observed_source_digests: dict[str, str],
    dependency_unknowns: list[dict[str, Any]],
    need_ids: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    excluded_paths = {
        item["relative_posix_path"] for item in exclusions
    }
    available_paths = {
        item["path"] for item in inventory_records
        if item["availability"] == "available"
        and not _is_excluded(item["path"], excluded_paths)
    }
    expected_observed = [
        {
            "kind": "source",
            "path": item["relative_posix_path"],
            "sha256": item["sha256"],
            "need_ids": need_ids,
        }
        for item in sources
    ]
    inferred: list[dict[str, Any]] = []
    required_unknowns: list[dict[str, Any]] = []
    read_cache = {
        item["relative_posix_path"] for item in sources
    }
    dependency_files = 0
    for source in sources:
        source_path = source["relative_posix_path"]
        if source["status"] != "PARSED":
            continue
        for specifier in source["imports"]:
            expected_observed.append({
                "kind": "import",
                "path": source_path,
                "module": specifier,
                "level": 0,
                "names": [],
                "need_ids": need_ids,
            })
            if not specifier.startswith(("./", "../")):
                continue
            resolved, failure = _resolve_local_reference_from_receipt(
                source_path=source_path,
                language=source["language"],
                specifier=specifier,
                available_paths=available_paths,
                excluded_paths=excluded_paths,
            )
            if resolved is None:
                required_unknowns.append({
                    "reason": failure or "UNRESOLVED_LOCAL_REFERENCE",
                    "path": source_path,
                    "module": specifier,
                    "need_ids": need_ids,
                })
                continue
            if resolved not in read_cache:
                if dependency_files >= _DEPENDENCY_LIMITS["max_dependency_files"]:
                    required_unknowns.append({
                        "reason": "FILE_LIMIT",
                        "path": source_path,
                        "module": specifier,
                        "need_ids": need_ids,
                    })
                    continue
                if resolved not in observed_source_digests:
                    # A resolved but unread dependency needs the adapter's exact
                    # source/module-scoped read failure, not silent omission.
                    if not any({
                        "reason": reason,
                        "path": source_path,
                        "module": specifier,
                        "need_ids": need_ids,
                    } in dependency_unknowns for reason in (
                        "BYTE_LIMIT", "SOURCE_CHANGED",
                        "EXCLUDED_DEPENDENCY", "SOURCE_CLEANUP_FAILED",
                    )):
                        raise MapBindingError("MAP_BINDING")
                    continue
                dependency_files += 1
                read_cache.add(resolved)
            if resolved not in observed_source_digests:
                raise MapBindingError("MAP_BINDING")
            expected_observed.append({
                "kind": "source",
                "path": resolved,
                "sha256": observed_source_digests[resolved],
                "need_ids": need_ids,
            })
            inferred.append({
                "source_path": source_path,
                "dependency_path": resolved,
                "sha256": observed_source_digests[resolved],
                "need_ids": need_ids,
            })
    unique_inferred = {
        (item["source_path"], item["dependency_path"]): item
        for item in inferred
    }
    return (
        _dedupe_dependency_records(expected_observed),
        list(unique_inferred.values()),
        required_unknowns,
    )


def _string_list(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) for item in value)
    )


def _valid_porcelain_status(code: Any) -> bool:
    if not isinstance(code, str) or len(code) != 2:
        return False
    if code in {"DD", "AU", "UD", "UA", "DU", "AA", "UU", "  "}:
        return False
    return (
        code in {"??", "!!"}
        or (code[0] in " MADT" and code[1] in " MDT")
    )











def _validate_adapter_receipt(
    receipt: Any, *, target: str, now: str, need_ids: list[str],
    question: str, statements: list[str],
) -> None:
    if isinstance(receipt, dict) and "followup" in receipt:
        _validate_followup_receipt(receipt, target=target, now=now, need_ids=need_ids,
                                   question=question, statements=statements)
        return
    if (
        not isinstance(receipt, dict)
        or set(receipt) != _RECEIPT_FIELDS
        or receipt["adapter_id"] != "rerg-repository-target-adapter"
        or receipt["adapter_version"] != "1"
        or receipt["evidence_class"] != "implementation_source"
        or receipt["target"] != target
        or receipt["captured_at"] != now
        or receipt["freshness"] != "current"
        or not isinstance(receipt["sources"], list)
        or len(receipt["sources"]) > 8
        or not isinstance(receipt["candidates"], list)
        or len(receipt["candidates"]) > 8
        or not isinstance(receipt["enumeration_truncated"], bool)
        or not isinstance(receipt["uninspected_surfaces"], list)
        or not all(
            _safe(path) or path == "."
            for path in receipt["uninspected_surfaces"]
        )
        or not isinstance(receipt["unknowns"], list)
        or not all(
            isinstance(item, str) and item for item in receipt["unknowns"]
        )
        or len(receipt["unknowns"]) != len(set(receipt["unknowns"]))
        or receipt["limitations"] != receipt["unknowns"]
    ):
        raise MapBindingError("MAP_BINDING")
    ranking = receipt["path_ranking"]
    if (
        not isinstance(ranking, dict)
        or set(ranking) != {
            "normalized_tokens", "inventory_records",
            "max_pre_stat_candidates", "max_initial_read_bytes",
            "phase1_candidates",
        }
        or ranking["max_pre_stat_candidates"] != 8
        or ranking["max_initial_read_bytes"] != 4_194_304
        or type(ranking["inventory_records"]) is not int
        or ranking["inventory_records"] < 0
        or not isinstance(ranking["normalized_tokens"], list)
        or len(ranking["normalized_tokens"]) > 64
        or not all(
            isinstance(item, str)
            and bool(item)
            and _TOKEN.fullmatch(item) is not None
            for item in ranking["normalized_tokens"]
        )
        or len(ranking["normalized_tokens"])
        != len(set(ranking["normalized_tokens"]))
        or not isinstance(ranking["phase1_candidates"], list)
        or len(ranking["phase1_candidates"]) > 8
    ):
        raise MapBindingError("MAP_BINDING")
    if receipt["source_binding"] is None or receipt["inventory"] is None:
        if not (
            receipt["source_binding"] is None
            and receipt["inventory"] is None
            and not receipt["sources"]
            and not receipt["candidates"]
            and not receipt["exclusions"]
            and not receipt["uninspected_surfaces"]
            and not ranking["normalized_tokens"]
            and ranking["inventory_records"] == 0
            and not ranking["phase1_candidates"]
            and receipt["enumeration_truncated"] is False
            and len(receipt["unknowns"]) == 1
            and receipt["dependencies"] == {
                "observed": [], "inferred": [], "unknowns": [],
                "limits": _DEPENDENCY_LIMITS,
            }
        ):
            raise MapBindingError("MAP_BINDING")
        return
    binding = receipt["source_binding"]
    inventory = receipt["inventory"]
    if ranking["normalized_tokens"] != _normalized_concepts(
        question, statements,
    ):
        raise MapBindingError("MAP_BINDING")
    if (
        not isinstance(binding, dict)
        or set(binding) != {
            "vcs", "head_oid", "scope_identity_sha256", "scope_prefix",
            "inventory_sha256", "worktree_state", "dirty_paths",
        }
        or binding["vcs"] != "git"
        or not _digest(binding["scope_identity_sha256"])
        or not _digest(binding["inventory_sha256"])
        or not isinstance(binding["head_oid"], str)
        or len(binding["head_oid"]) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in binding["head_oid"])
        or not isinstance(binding["scope_prefix"], str)
        or (
            binding["scope_prefix"] != ""
            and not _safe(binding["scope_prefix"])
        )
        or binding["worktree_state"] not in {"clean", "dirty"}
        or not _string_list(binding["dirty_paths"])
        or binding["dirty_paths"] != sorted(set(binding["dirty_paths"]))
        or any(not _safe(path) for path in binding["dirty_paths"])
        or not isinstance(inventory, dict)
        or set(inventory) != {
            "schema_version", "head_oid", "scope_identity_sha256",
            "scope_prefix", "records", "status", "exclusions",
            "ignore_policy", "filter_config_keys_sha256",
            "disabled_filter_drivers", "inventory_sha256",
            "worktree_state", "dirty_paths",
        }
        or inventory["schema_version"] != "rerg-git-worktree-inventory/v1"
        or inventory["head_oid"] != binding["head_oid"]
        or inventory["scope_identity_sha256"] != binding["scope_identity_sha256"]
        or inventory["scope_prefix"] != binding["scope_prefix"]
        or inventory["inventory_sha256"] != binding["inventory_sha256"]
        or inventory["worktree_state"] != binding["worktree_state"]
        or inventory["dirty_paths"] != binding["dirty_paths"]
        or inventory["ignore_policy"] != "git-exclude-standard"
        or not _digest(inventory["filter_config_keys_sha256"])
        or not _string_list(inventory["disabled_filter_drivers"])
        or inventory["disabled_filter_drivers"] != sorted(
            set(inventory["disabled_filter_drivers"])
        )
        or any(
            not driver
            or len(driver) > 64
            or not (
                "0" <= driver[0] <= "9"
                or "A" <= driver[0] <= "Z"
                or "a" <= driver[0] <= "z"
            )
            or any(
                not (
                    "0" <= character <= "9"
                    or "A" <= character <= "Z"
                    or "a" <= character <= "z"
                    or character in {"_", "-"}
                )
                for character in driver
            )
            for driver in inventory["disabled_filter_drivers"]
        )
        or not isinstance(inventory["records"], list)
        or ranking["inventory_records"] != len(inventory["records"])
        or not isinstance(inventory["status"], list)
        or not isinstance(inventory["exclusions"], list)
    ):
        raise MapBindingError("MAP_BINDING")
    scope_identity = {
        "schema_version": "rerg-git-scope-identity/v1",
        "head_oid": binding["head_oid"],
        "scope_prefix": binding["scope_prefix"],
    }
    inventory_payload = {
        key: copy.deepcopy(value)
        for key, value in inventory.items()
        if key not in {"inventory_sha256", "worktree_state", "dirty_paths"}
    }
    if (
        _canonical_sha256(scope_identity) != binding["scope_identity_sha256"]
        or _canonical_sha256(inventory_payload) != binding["inventory_sha256"]
        or binding["worktree_state"]
        != ("dirty" if binding["dirty_paths"] else "clean")
    ):
        raise MapBindingError("MAP_BINDING")
    record_paths = []
    for record in inventory["records"]:
        if (
            not isinstance(record, dict)
            or set(record) != {
                "path", "tracking", "mode", "oid", "stage", "status",
                "availability",
            }
            or not _safe(record["path"])
            or record["tracking"] not in {
                "tracked", "untracked", "status-only",
            }
            or record["availability"] not in {"available", "missing"}
            or (
                record["status"] != "  "
                and not _valid_porcelain_status(record["status"])
            )
            or (
                record["tracking"] == "tracked"
                and (
                    record["mode"] not in {"100644", "100755"}
                    or not _oid(record["oid"])
                    or record["stage"] != 0
                )
            )
            or (
                record["tracking"] in {"untracked", "status-only"}
                and (
                    record["mode"] is not None
                    or record["oid"] is not None
                    or record["stage"] is not None
                )
            )
            or (
                record["tracking"] == "status-only"
                and record["availability"] != "missing"
            )
        ):
            raise MapBindingError("MAP_BINDING")
        record_paths.append(record["path"])
    if record_paths != sorted(set(record_paths)):
        raise MapBindingError("MAP_BINDING")
    if (
        any(
            not isinstance(item, dict)
            or set(item) != {"path", "code"}
            or not _safe(item["path"])
            or not _valid_porcelain_status(item["code"])
            for item in inventory["status"]
        )
        or [item["path"] for item in inventory["status"]]
        != sorted(set(item["path"] for item in inventory["status"]))
        or binding["dirty_paths"]
        != [item["path"] for item in inventory["status"]]
        or any(
            not isinstance(item, dict)
            or set(item) != {"path", "category"}
            or not _safe(item["path"])
            or item["category"] not in {"symlink", "submodule"}
            for item in inventory["exclusions"]
        )
    ):
        raise MapBindingError("MAP_BINDING")
    status_by_path = {
        item["path"]: item["code"] for item in inventory["status"]
    }
    if any(
        record["status"] != status_by_path.get(
            record["path"],
            "??" if record["tracking"] == "untracked" else "  ",
        )
        or (
            record["availability"] == "missing"
            and "D" not in record["status"]
        )
        or (
            record["availability"] == "available"
            and "D" in record["status"]
        )
        for record in inventory["records"]
    ):
        raise MapBindingError("MAP_BINDING")
    phase1 = ranking["phase1_candidates"]
    if any(
        not isinstance(item, dict)
        or set(item) != {
            "relative_posix_path", "path_score", "matched_concepts",
            "parser_supported", "marginal_at_selection", "rank",
        }
        or not _safe(item["relative_posix_path"])
        or type(item["path_score"]) is not int
        or item["path_score"] <= 0
        or not isinstance(item["parser_supported"], bool)
        or type(item["marginal_at_selection"]) is not int
        or item["marginal_at_selection"] < 0
        or type(item["rank"]) is not int
        or not isinstance(item["matched_concepts"], list)
        or not all(
            isinstance(token, str) and token
            for token in item["matched_concepts"]
        )
        or (
            item["path_score"],
            item["matched_concepts"],
        ) != _path_ranking_facts(
            item["relative_posix_path"], ranking["normalized_tokens"]
        )
        for item in phase1
    ) or len({
        item["relative_posix_path"] for item in phase1
    }) != len(phase1):
        raise MapBindingError("MAP_BINDING")
    excluded_paths = {
        item["relative_posix_path"] for item in receipt["exclusions"]
    }
    def excluded(path: str) -> bool:
        return any(
            path == excluded_path or path.startswith(excluded_path + "/")
            for excluded_path in excluded_paths
        )

    admitted_inventory_paths = [
        item["path"] for item in inventory["records"]
        if not excluded(item["path"])
    ]
    eligible_inventory_paths = [
        item["path"] for item in inventory["records"]
        if item["availability"] == "available"
        and not excluded(item["path"])
    ]
    if phase1 != _select_rankings(
        eligible_inventory_paths, ranking["normalized_tokens"]
    ):
        raise MapBindingError("MAP_BINDING")
    sources = receipt["sources"]
    if any(
        not isinstance(item, dict)
        or set(item) != _SOURCE_FIELDS
        or not _safe(item["relative_posix_path"])
        or not _digest(item["sha256"])
        or item["regular_file"] is not True
        or item["confined"] is not True
        or item["race_checked"] is not True
        or type(item["path_score"]) is not int
        or item["path_score"] <= 0
        or any(
            not isinstance(values, list)
            or not all(isinstance(value, str) and value for value in values)
            for values in (
                item["matched_concepts"], item["symbols"], item["imports"],
                item["literal_tokens"], item["parse_unknowns"],
            )
        )
        or item["language"] not in {
            "python", "javascript", "typescript", "tsx", "unsupported",
        }
        or not isinstance(item["status"], str)
        or not item["status"]
        or (
            item["status"] != "PARSED"
            and (
                item["symbols"]
                or item["imports"]
                or item["literal_tokens"]
            )
        )
        or (
            item["language"] == "unsupported"
            and item["status"] != "UNSUPPORTED_LANGUAGE"
        )
        or (
            item["language"] != "unsupported"
            and item["status"] not in {
                "PARSED", "SYNTAX_ERROR",
                "INVALID_SOURCE_ENCODING", "PARSER_RESOURCE_LIMIT",
                f"PARSER_UNAVAILABLE:{item['language']}",
            }
        )
        or not _source_status_coherent(item)
        or len(item["parse_unknowns"]) != len(set(item["parse_unknowns"]))
        or len(item["symbols"]) > 128
        or len(item["imports"]) > 128
        or len(item["literal_tokens"]) > 64
        or len(item["parse_unknowns"]) > 128
        for item in sources
    ) or len({
        item["relative_posix_path"] for item in sources
    }) != len(sources):
        raise MapBindingError("MAP_BINDING")
    exclusions = receipt["exclusions"]
    if (
        not isinstance(exclusions, list)
        or any(
            not isinstance(item, dict)
            or set(item) != {"category", "relative_posix_path"}
            or item["category"] not in {
                "runtime", "generated", "sensitive", "ignore_rules",
                "symlink", "submodule",
            }
            or not _safe(item["relative_posix_path"])
            for item in exclusions
        )
        or exclusions != sorted(
            exclusions, key=lambda item: item["relative_posix_path"]
        )
        or len({
            item["relative_posix_path"] for item in exclusions
        }) != len(exclusions)
    ):
        raise MapBindingError("MAP_BINDING")
    expected_exclusions = {
        item["path"]: {
            "category": item["category"],
            "relative_posix_path": item["path"],
        }
        for item in inventory["exclusions"]
    }
    for record in inventory["records"]:
        excluded = _source_exclusion(record["path"])
        if excluded is not None:
            category, path = excluded
            expected_exclusions[path] = {
                "category": category,
                "relative_posix_path": path,
            }
    if exclusions != sorted(
        expected_exclusions.values(),
        key=lambda item: item["relative_posix_path"],
    ):
        raise MapBindingError("MAP_BINDING")
    dependencies = receipt["dependencies"]
    if (
        not isinstance(dependencies, dict)
        or set(dependencies) != {"observed", "inferred", "unknowns", "limits"}
        or dependencies["limits"] != _DEPENDENCY_LIMITS
        or not all(
            isinstance(dependencies[field], list)
            for field in ("observed", "inferred", "unknowns")
        )
    ):
        raise MapBindingError("MAP_BINDING")
    for item in dependencies["observed"]:
        if not isinstance(item, dict):
            raise MapBindingError("MAP_BINDING")
        if item.get("kind") == "source":
            expected = {"kind", "path", "sha256", "need_ids"}
            valid = (
                set(item) == expected
                and _safe(item["path"])
                and _digest(item["sha256"])
            )
        elif item.get("kind") == "import":
            expected = {
                "kind", "path", "module", "level", "names", "need_ids",
            }
            valid = (
                set(item) == expected
                and _safe(item["path"])
                and isinstance(item["module"], str)
                and type(item["level"]) is int
                and isinstance(item["names"], list)
                and all(isinstance(name, str) for name in item["names"])
            )
        else:
            valid = False
        if (
            not valid
            or item["need_ids"] != need_ids
        ):
            raise MapBindingError("MAP_BINDING")
    if any(
        not isinstance(item, dict)
        or set(item) != {
            "source_path", "dependency_path", "sha256", "need_ids",
        }
        or not _safe(item["source_path"])
        or not _safe(item["dependency_path"])
        or not _digest(item["sha256"])
        or item["need_ids"] != need_ids
        for item in dependencies["inferred"]
    ):
        raise MapBindingError("MAP_BINDING")
    if any(
        not isinstance(item, dict)
        or set(item) not in (
            {"reason", "need_ids"},
            {"reason", "path", "need_ids"},
            {"reason", "path", "module", "need_ids"},
        )
        or not isinstance(item["reason"], str)
        or not item["reason"]
        or ("path" in item and not _safe(item["path"]))
        or ("module" in item and not isinstance(item["module"], str))
        or item["need_ids"] != need_ids
        for item in dependencies["unknowns"]
    ):
        raise MapBindingError("MAP_BINDING")
    source_by_path = {
        item["relative_posix_path"]: item for item in sources
    }
    phase1_by_path = {
        item["relative_posix_path"]: item for item in phase1
    }
    if any(
        item["relative_posix_path"] not in phase1_by_path
        or item["path_score"]
        != phase1_by_path[item["relative_posix_path"]]["path_score"]
        or item["matched_concepts"]
        != phase1_by_path[item["relative_posix_path"]]["matched_concepts"]
        for item in sources
    ):
        raise MapBindingError("MAP_BINDING")
    phase1_order = {
        item["relative_posix_path"]: index
        for index, item in enumerate(phase1)
    }
    if sources != sorted(
        sources,
        key=lambda item: phase1_order[item["relative_posix_path"]],
    ):
        raise MapBindingError("MAP_BINDING")
    if receipt["uninspected_surfaces"] != sorted(
        set(admitted_inventory_paths) - set(source_by_path)
    ):
        raise MapBindingError("MAP_BINDING")

    observed_source_digests: dict[str, str] = {}
    observed_imports: list[dict[str, Any]] = []
    for item in dependencies["observed"]:
        if item["kind"] != "source":
            observed_imports.append(item)
            continue
        path = item["path"]
        if path in observed_source_digests:
            raise MapBindingError("MAP_BINDING")
        observed_source_digests[path] = item["sha256"]
    observed_source_paths = set(observed_source_digests)
    expected_observed, expected_inferred, required_dependency_unknowns = (
        _expected_dependency_receipt_subset(
            sources=sources,
            inventory_records=inventory["records"],
            exclusions=exclusions,
            observed_source_digests=observed_source_digests,
            dependency_unknowns=dependencies["unknowns"],
            need_ids=need_ids,
        )
    )
    expected_observed_sources = {
        item["path"] for item in expected_observed
        if item["kind"] == "source"
    }
    expected_imports = [
        item for item in expected_observed if item["kind"] == "import"
    ]
    if (
        observed_source_paths != expected_observed_sources
        or observed_imports != expected_imports
        or any(
            item["kind"] == "import"
            and item["path"] not in observed_source_paths
            for item in dependencies["observed"]
        )
        or any(
            observed_source_digests[path] != source["sha256"]
            for path, source in source_by_path.items()
            if path in observed_source_digests
        )
    ):
        raise MapBindingError("MAP_BINDING")
    inferred_pairs = [
        (item["source_path"], item["dependency_path"])
        for item in dependencies["inferred"]
    ]
    # This closes receipt relations derivable from parser-observed imports,
    # inventory paths, resolver order, caps, and digest self-consistency. It
    # does not authenticate valid-looking alternative parser facts in a wholly
    # resealed private receipt.
    if (
        len(inferred_pairs) != len(set(inferred_pairs))
        or dependencies["inferred"] != expected_inferred
        or any(item not in dependencies["unknowns"] for item in required_dependency_unknowns)
    ):
        raise MapBindingError("MAP_BINDING")

    candidates = receipt["candidates"]
    if any(
        not isinstance(item, dict)
        or set(item) != {
            "relative_posix_path", "sha256", "score", "authorizing",
        }
        or not _safe(item["relative_posix_path"])
        or not _digest(item["sha256"])
        or type(item["score"]) is not int
        or item["score"] <= 0
        or item["authorizing"] is not False
        or item["relative_posix_path"] not in source_by_path
        or source_by_path[item["relative_posix_path"]]["sha256"]
        != item["sha256"]
        or item["score"]
        != source_by_path[item["relative_posix_path"]]["path_score"]
        for item in candidates
    ):
        raise MapBindingError("MAP_BINDING")
    expected_candidates = [
        {
            "relative_posix_path": item["relative_posix_path"],
            "sha256": item["sha256"],
            "score": item["path_score"],
            "authorizing": False,
        }
        for item in sources
    ][:8]
    dependency_unknown_reasons = {
        item["reason"] for item in dependencies["unknowns"]
    }
    parser_unknown_reasons = {
        reason
        for source in sources
        for reason in source["parse_unknowns"]
    }
    ambiguous = (
        len(sources) > 1
        and sources[0]["path_score"] == sources[1]["path_score"]
    )
    consistency = {
        "SENSITIVE_SURFACE_EXCLUDED": any(
            item["category"] == "sensitive" for item in exclusions
        ),
        "INSUFFICIENT_RELEVANCE": (
            not phase1 or not sources
        ),
        "AMBIGUOUS_RELEVANCE": ambiguous,
        "SEMANTIC_RELEVANCE_UNINTERPRETED": bool(sources),
        "DIRTY_IMPLEMENTATION_SOURCE": binding["worktree_state"] == "dirty",
        "UNAVAILABLE_SURFACE": any(
            item["availability"] == "missing"
            for item in inventory["records"]
        ),
    }
    if (
        candidates != expected_candidates
        or receipt["enumeration_truncated"] is not False
        or receipt["uninspected_surfaces"]
        != sorted(set(receipt["uninspected_surfaces"]))
        or not dependency_unknown_reasons <= set(receipt["unknowns"])
        or not parser_unknown_reasons <= set(receipt["unknowns"])
        or any(
            (reason in receipt["unknowns"]) is not expected
            for reason, expected in consistency.items()
        )
    ):
        raise MapBindingError("MAP_BINDING")





def _resolve_citation_reference(identifier, citations, artifacts):
    """Resolve one supplied citation association and, when safe, its bytes."""
    citation = citations.get(identifier)
    if citation is None:
        return {'properties': ('missing_citation',), 'candidate_role': False, 'span': None}
    artifact = artifacts.get(citation['artifact_id'])
    if artifact is None:
        return {'properties': ('missing_artifact',), 'candidate_role': False, 'span': None}

    properties = set()
    if 'outside_view' in artifact['limitations']:
        properties.add('outside_view')
    data = artifact['data'].encode('utf-8')
    start, end = citation['start_byte'], citation['end_byte']
    bad_span = start < 0 or end > len(data) or start >= end
    try:
        data[:start].decode('utf-8')
        data[start:end].decode('utf-8')
        data[end:].decode('utf-8')
    except UnicodeError:
        bad_span = True
    if (
        hashlib.sha256(data).hexdigest() != artifact['representation_sha256']
        or citation['representation_sha256'] != artifact['representation_sha256']
        or bad_span
    ):
        properties.add('invalid_source_association')
    if bool(set(artifact['limitations']) - {'outside_view'}):
        properties.add('limited_evidence')
    return {
        'properties': tuple(sorted(properties)),
        'candidate_role': artifact['role'] == 'candidate',
        'span': None if properties else data[start:end],
    }


def _evaluate_source_relation(relation, citations, artifacts, cache=None):
    """Resolve only captured byte spans; never acquire or interpret source."""
    if cache is None:
        cache = {}
    identifiers = (
        [relation["left_citation_id"], relation["right_citation_id"]]
        if relation["kind"] == "source_same" else [relation["citation_id"]]
    )
    facts = []
    for identifier in identifiers:
        if identifier not in cache:
            cache[identifier] = _resolve_citation_reference(
                identifier, citations, artifacts,
            )
        facts.append(cache[identifier])
    properties = {property_ for fact in facts for property_ in fact['properties']}
    if any(fact['candidate_role'] for fact in facts):
        properties.add('limited_evidence')
    if 'missing_citation' in properties or 'missing_artifact' in properties:
        state, gap = "unresolved", "missing_citation"
    elif 'outside_view' in properties:
        state, gap = "outside_view", "outside_view"
    elif properties:
        state, gap = "unresolved", "limited_evidence"
    else:
        spans = [fact['span'] for fact in facts]
        if (
            relation["kind"] == "source_same" and spans[0] != spans[1]
            or relation["kind"] == "source_equals"
            and spans[0] != relation["expected"].encode("utf-8")
        ):
            state, gap = "contradicted", "false_requirement"
        else:
            state, gap = "supported", None
    return (
        {"id": relation["id"], "state": state, "citation_ids": sorted(set(identifiers))},
        None if gap is None else {"relation_id": relation["id"], "property": gap},
    )
