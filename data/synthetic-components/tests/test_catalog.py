from __future__ import annotations

from pathlib import Path

import pytest

from haystack_component_vulnerability_benchmark.catalog import (
    CatalogError,
    derive_spans,
    instance_id,
    load_catalog,
    load_recipes,
    load_repositories,
    normalize_path,
    primary_target,
    tree_digest,
)


def test_counts_match_the_declared_expectations(root: Path, pairs: list[dict]) -> None:
    catalog = load_catalog(root)
    expected = catalog["expected_counts"]
    repositories = load_repositories(root)
    assert len(repositories) == expected["repositories"]
    assert sum(not r["excluded"] for r in repositories) == expected["included"]
    assert len(pairs) == expected["pairs"]
    assert sum(1 for p in pairs if p.get("placebo_instance_id")) == expected["placebo_controls"]


def test_every_pair_declares_a_known_recipe_and_cwe(root: Path, pairs: list[dict]) -> None:
    recipes = load_recipes(root)
    for pair in pairs:
        recipe = recipes[pair["recipe_id"]]
        assert recipe["kind"] == "vulnerability"
        assert pair["cwe"] in recipe["cwes"]


def test_recipe_coverage_is_balanced(root: Path, pairs: list[dict]) -> None:
    """The internal benchmark had one family at 26% of all pairs; cap it here."""
    recipes = load_recipes(root)
    families = {rid for rid, r in recipes.items() if r["kind"] == "vulnerability"}
    counts: dict[str, int] = {}
    for pair in pairs:
        counts[pair["recipe_id"]] = counts.get(pair["recipe_id"], 0) + 1
    assert set(counts) == families, "every vulnerability family must be represented"
    assert max(counts.values()) <= 3


def test_delta_fingerprints_are_unique(pairs: list[dict]) -> None:
    fingerprints = [pair["delta_fingerprint"] for pair in pairs]
    assert len(set(fingerprints)) == len(fingerprints)


def test_instance_ids_are_derived(root: Path, pairs: list[dict]) -> None:
    corpus_id = load_catalog(root)["corpus_id"]
    for pair in pairs:
        for member in ("baseline", "mutant"):
            assert pair[f"{member}_instance_id"] == instance_id(corpus_id, pair["pair_id"], member)


def test_primary_target_is_the_sink(pairs: list[dict]) -> None:
    for pair in pairs:
        assert primary_target(pair)["role"] == "sink"


@pytest.mark.parametrize("value", ["", ".", "../escape", "/etc/passwd/../.."])
def test_normalize_path_rejects_escapes(value: str) -> None:
    with pytest.raises(CatalogError):
        normalize_path(value)


def test_tree_digest_encoding(tmp_path: Path) -> None:
    import os

    tree = tmp_path / "tree"
    (tree / "pkg").mkdir(parents=True)
    (tree / "a.py").write_text("x = 1\n")
    (tree / "pkg/b.py").write_text("y = 2\n")
    (tree / "run.sh").write_text("#!/bin/sh\n")
    os.chmod(tree / "run.sh", 0o755)
    (tree / "link").symlink_to("a.py")
    original, count = tree_digest(tree)
    assert count == 4

    (tree / "__pycache__").mkdir()
    (tree / "__pycache__/junk.pyc").write_bytes(b"\x00")
    assert tree_digest(tree) == (original, count), "excluded names must not affect the digest"

    os.chmod(tree / "run.sh", 0o644)
    assert tree_digest(tree)[0] != original, "the executable bit must be visible"
    os.chmod(tree / "run.sh", 0o755)
    assert tree_digest(tree)[0] == original

    (tree / "a.py").write_text("x = 2\n")
    assert tree_digest(tree)[0] != original


def test_derive_spans_handles_a_pure_insertion() -> None:
    baseline = ["a", "b"]
    variant = ["a", "inserted", "b"]
    spans = derive_spans(baseline, variant)
    assert spans is not None
    (base_start, base_end), (var_start, var_end) = spans
    assert base_start >= 1 and base_end >= base_start
    assert (var_start, var_end) == (2, 2)


def test_derive_spans_returns_none_when_identical() -> None:
    assert derive_spans(["a"], ["a"]) is None
