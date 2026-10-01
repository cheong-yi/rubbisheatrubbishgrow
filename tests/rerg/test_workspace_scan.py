import pytest


def test_defaults_are_visible_immutable_and_disjoint():
    from rerg.workspace_scan import classify_workspace_entries

    entries = ["?? .gjc/state.json", "!! .omx/cache", " M rerg/raw_intake.py"]
    result = classify_workspace_entries(entries)
    assert result["schema_version"] == "rerg-workspace-scan/v1"
    assert result["default_allowed_prefixes"] == [".gjc", ".omx"]
    assert [item["path"] for item in result["allowed_runtime_residue"]] == [
        ".gjc/state.json", ".omx/cache"
    ]
    assert [item["path"] for item in result["product_dirt"]] == ["rerg/raw_intake.py"]
    assert result["rejected_entries"] == []
    partitions = [result[name] for name in ("allowed_runtime_residue", "product_dirt", "rejected_entries")]
    assert sum(map(len, partitions)) == len(entries)
    assert not ({id(item) for item in partitions[0]} & {id(item) for item in partitions[1]})


def test_controller_allowlist_is_additive_and_validated():
    from rerg.workspace_scan import WorkspaceScanError, classify_workspace_entries

    result = classify_workspace_entries(
        ["?? .gjc/state", "?? .local-tool/state", "?? product.py"],
        additional_allowed_prefixes=[".local-tool"],
    )
    assert result["additional_allowed_prefixes"] == [".local-tool"]
    assert [item["path"] for item in result["allowed_runtime_residue"]] == [
        ".gjc/state", ".local-tool/state"
    ]
    for invalid in ([".gjc"], ["../escape"], ["/absolute"], ["a", "a/b"]):
        with pytest.raises(WorkspaceScanError):
            classify_workspace_entries([], additional_allowed_prefixes=invalid)


def test_malformed_porcelain_and_rename_copy_endpoints_fail_closed():
    from rerg.workspace_scan import classify_workspace_entries

    malformed = classify_workspace_entries(["xx .gjc/hidden"])
    assert malformed["allowed_runtime_residue"] == []
    assert malformed["product_dirt"] == []
    assert malformed["rejected_entries"] == [{
        "raw": "xx .gjc/hidden", "reason": "INVALID_ENTRY"
    }]

    result = classify_workspace_entries([
        "R  product.py -> .gjc/product.py",
        "C  .omx/source -> product-copy.py",
        "R  .gjc/old -> .omx/new",
    ])
    assert [item["paths"] for item in result["product_dirt"]] == [
        ["product.py", ".gjc/product.py"],
        [".omx/source", "product-copy.py"],
    ]
    assert [item["paths"] for item in result["allowed_runtime_residue"]] == [
        [".gjc/old", ".omx/new"]
    ]


def test_collapsed_untracked_and_ignored_directories_are_normalized():
    from rerg.workspace_scan import classify_workspace_entries

    entries = ["?? .gjc/", "!! .omx/", "?? product/"]
    result = classify_workspace_entries(entries)

    assert result["allowed_runtime_residue"] == [
        {"raw": "?? .gjc/", "path": ".gjc", "paths": [".gjc"]},
        {"raw": "!! .omx/", "path": ".omx", "paths": [".omx"]},
    ]
    assert result["product_dirt"] == [
        {"raw": "?? product/", "path": "product", "paths": ["product"]}
    ]
    assert result["rejected_entries"] == []


def test_collapsed_directory_normalization_does_not_apply_to_endpoints():
    from rerg.workspace_scan import classify_workspace_entries

    entries = [
        "R  product/ -> .gjc/",
        "C  .omx/ -> product/",
    ]
    result = classify_workspace_entries(entries)

    assert result["allowed_runtime_residue"] == []
    assert result["product_dirt"] == []
    assert result["rejected_entries"] == [
        {"raw": entry, "reason": "INVALID_ENTRY"} for entry in entries
    ]


def test_porcelain_state_pair_equivalence_classes():
    from rerg.workspace_scan import classify_workspace_entries

    result = classify_workspace_entries([
        " M product.py",
        "?? .gjc/state",
        "!! .omx/cache",
        "   blank-status.py",
        "XM invalid-status.py",
        "R  product.py -> .gjc/product.py",
        "C  .gjc/source -> .omx/copy",
        "R  missing-arrow.py",
        " M unexpected -> arrow",
        "R  one -> two -> three",
    ])
    assert [item["raw"] for item in result["product_dirt"]] == [
        " M product.py",
        "R  product.py -> .gjc/product.py",
    ]
    assert [item["raw"] for item in result["allowed_runtime_residue"]] == [
        "?? .gjc/state",
        "!! .omx/cache",
        "C  .gjc/source -> .omx/copy",
    ]
    assert [item["raw"] for item in result["rejected_entries"]] == [
        "   blank-status.py",
        "XM invalid-status.py",
        "R  missing-arrow.py",
        " M unexpected -> arrow",
        "R  one -> two -> three",
    ]
