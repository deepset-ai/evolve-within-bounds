"""Negative tests for the release gate itself.

Validation is what stands between an authoring mistake and a benchmark that
quietly measures nothing, so each failure path is exercised directly.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from haystack_component_vulnerability_benchmark.validate import validate_catalog


@pytest.fixture
def staging(tmp_path: Path, root: Path) -> Path:
    destination = tmp_path / "benchmark"
    shutil.copytree(
        root, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache")
    )
    return destination


def _pairs(staging: Path) -> list[dict]:
    return [json.loads(line) for line in (staging / "data/pairs.jsonl").read_text().splitlines()]


def _write_pairs(staging: Path, pairs: list[dict]) -> None:
    (staging / "data/pairs.jsonl").write_text(
        "".join(json.dumps(p, sort_keys=True) + "\n" for p in pairs), encoding="utf-8"
    )


def _errors(staging: Path) -> list[str]:
    report = validate_catalog(staging)
    return report["errors"]


def test_clean_catalog_validates(staging: Path) -> None:
    report = validate_catalog(staging)
    assert report["ok"], report["errors"][:5]


def test_corrupt_tree_digest_is_caught(staging: Path) -> None:
    catalog = json.loads((staging / "data/repositories.json").read_text())
    catalog["repositories"][0]["tree_sha256"] = "0" * 64
    (staging / "data/repositories.json").write_text(json.dumps(catalog))
    assert any("tree_sha256 mismatch" in e for e in _errors(staging))


def test_edited_corpus_file_is_caught(staging: Path) -> None:
    catalog = json.loads((staging / "data/repositories.json").read_text())
    target = staging / catalog["repositories"][0]["path"] / "README.md"
    target.write_text(target.read_text() + "\ndrift\n")
    assert any("tree_sha256 mismatch" in e for e in _errors(staging))


def test_wrong_patch_hash_is_caught(staging: Path) -> None:
    pairs = _pairs(staging)
    pairs[0]["patch_sha256"] = "0" * 64
    _write_pairs(staging, pairs)
    assert any("sha256 mismatch" in e for e in _errors(staging))


def test_hand_edited_span_is_caught(staging: Path) -> None:
    """Spans are derived; a hand-edited one must not survive."""
    pairs = _pairs(staging)
    pairs[0]["targets"][0]["mutant_line_start"] += 5
    pairs[0]["targets"][0]["mutant_line_end"] += 5
    _write_pairs(staging, pairs)
    assert any("!= derived" in e for e in _errors(staging))


def test_undeclared_target_is_caught(staging: Path) -> None:
    pairs = _pairs(staging)
    multi = next(p for p in pairs if len(p["targets"]) > 1)
    multi["targets"] = multi["targets"][:1]
    _write_pairs(staging, pairs)
    assert any("declared" in e for e in _errors(staging))


def test_duplicate_instance_id_is_caught(staging: Path) -> None:
    pairs = _pairs(staging)
    pairs[1]["mutant_instance_id"] = pairs[0]["mutant_instance_id"]
    _write_pairs(staging, pairs)
    assert any("duplicate instance id" in e for e in _errors(staging))


def test_non_derived_instance_id_is_caught(staging: Path) -> None:
    pairs = _pairs(staging)
    pairs[0]["mutant_instance_id"] = "instance-" + "a" * 20
    _write_pairs(staging, pairs)
    assert any("not the derived value" in e for e in _errors(staging))


def test_cwe_outside_the_recipe_is_caught(staging: Path) -> None:
    pairs = _pairs(staging)
    pairs[0]["cwe"] = "CWE-306"
    _write_pairs(staging, pairs)
    assert any("not declared by" in e for e in _errors(staging))


def test_two_sinks_are_caught(staging: Path) -> None:
    pairs = _pairs(staging)
    multi = next(p for p in pairs if len(p["targets"]) > 1)
    for target in multi["targets"]:
        target["role"] = "sink"
    _write_pairs(staging, pairs)
    assert any("exactly one sink" in e for e in _errors(staging))


def test_declared_count_drift_is_caught(staging: Path) -> None:
    catalog = json.loads((staging / "data/repositories.json").read_text())
    catalog["expected_counts"]["pairs"] += 1
    (staging / "data/repositories.json").write_text(json.dumps(catalog))
    assert any("expected pairs" in e for e in _errors(staging))


def test_duplicate_delta_is_caught(staging: Path) -> None:
    """Two pairs carrying the identical edit is the failure this gate exists for."""
    pairs = _pairs(staging)
    source = staging / pairs[0]["patch"]
    shutil.copyfile(source, staging / pairs[1]["patch"])
    import hashlib

    pairs[1]["patch_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    _write_pairs(staging, pairs)
    assert any("delta_fingerprint collision" in e for e in _errors(staging))
