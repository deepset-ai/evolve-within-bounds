from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from haystack_component_vulnerability_benchmark.catalog import primary_target
from haystack_component_vulnerability_benchmark.materialize import (
    MaterializationError,
    _prepare_output,
    materialize,
    verify_mutation,
)


def test_materialize_one_pair(tmp_path: Path, root: Path, triplet: dict) -> None:
    output = tmp_path / "instances"
    report = materialize(
        root=root,
        output=output,
        pair_ids={triplet["pair_id"]},
        answer_key=tmp_path / "answer_key.json",
    )
    assert report["pairs"] == 1
    assert report["instances"] == 3, "a triplet contributes baseline, mutant and placebo"

    sink = primary_target(triplet)
    baseline = output / triplet["baseline_instance_id"] / sink["path"]
    mutant = output / triplet["mutant_instance_id"] / sink["path"]
    assert baseline.read_bytes() != mutant.read_bytes()

    manifest = [
        json.loads(line) for line in (output / "scan_manifest.jsonl").read_text().splitlines()
    ]
    assert len(manifest) == 3
    assert all(set(row) == {"instance_id", "path"} for row in manifest), "manifest must be blinded"
    assert not (output / "answer_key.json").exists()


def test_materialize_into_a_git_work_tree(
    tmp_path: Path, root: Path, single_file_pair: dict
) -> None:
    """git apply resolves paths against an enclosing work tree and silently skips
    everything outside the current prefix, exiting zero. An output directory inside
    a repository must still produce a patched mutant."""
    enclosing = tmp_path / "enclosing-repo"
    enclosing.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=enclosing, check=True)
    output = enclosing / "materialized"
    materialize(
        root=root,
        output=output,
        pair_ids={single_file_pair["pair_id"]},
        answer_key=tmp_path / "answer_key.json",
    )
    sink = primary_target(single_file_pair)
    baseline = output / single_file_pair["baseline_instance_id"] / sink["path"]
    mutant = output / single_file_pair["mutant_instance_id"] / sink["path"]
    assert baseline.read_bytes() != mutant.read_bytes()


def test_multi_file_mutation_changes_every_declared_target(
    tmp_path: Path, root: Path, multi_file_pair: dict
) -> None:
    output = tmp_path / "instances"
    materialize(
        root=root,
        output=output,
        pair_ids={multi_file_pair["pair_id"]},
        answer_key=tmp_path / "answer_key.json",
    )
    for target in multi_file_pair["targets"]:
        baseline = output / multi_file_pair["baseline_instance_id"] / target["path"]
        mutant = output / multi_file_pair["mutant_instance_id"] / target["path"]
        assert baseline.read_bytes() != mutant.read_bytes(), target["path"]


def test_verify_mutation_requires_exactly_the_declared_set(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    variant = tmp_path / "variant"
    for tree in (baseline, variant):
        (tree / "src").mkdir(parents=True)
        (tree / "src/a.py").write_text("value = 1\n")
        (tree / "src/b.py").write_text("other = 1\n")

    with pytest.raises(MaterializationError, match="unchanged"):
        verify_mutation(baseline, variant, ["src/a.py"], "pair-x", "mutant")

    (variant / "src/a.py").write_text("value = unsafe()\n")
    verify_mutation(baseline, variant, ["src/a.py"], "pair-x", "mutant")

    (variant / "src/b.py").write_text("other = 2\n")
    with pytest.raises(MaterializationError, match="undeclared"):
        verify_mutation(baseline, variant, ["src/a.py"], "pair-x", "mutant")


def test_corpus_digest_preflight(tmp_path: Path, root: Path, single_file_pair: dict) -> None:
    import shutil

    staging = tmp_path / "benchmark"
    shutil.copytree(root, staging, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    repositories = json.loads((staging / "data/repositories.json").read_text())
    repositories["repositories"][0]["tree_sha256"] = "0" * 64
    (staging / "data/repositories.json").write_text(json.dumps(repositories))
    with pytest.raises(MaterializationError, match="digest"):
        materialize(
            root=staging,
            output=tmp_path / "out",
            answer_key=tmp_path / "answer_key.json",
        )


def test_output_guards(tmp_path: Path) -> None:
    benchmark = tmp_path / "benchmark"
    (benchmark / "corpus").mkdir(parents=True)
    with pytest.raises(MaterializationError, match="unsafe"):
        _prepare_output(tmp_path, benchmark, force=True)
    with pytest.raises(MaterializationError, match="overlaps"):
        _prepare_output(
            benchmark / "corpus/out", benchmark, True, protected=(benchmark / "corpus",)
        )

    regular = tmp_path / "file"
    regular.write_text("keep")
    with pytest.raises(MaterializationError, match="not a directory"):
        _prepare_output(regular, benchmark, force=True)
    assert regular.read_text() == "keep"


def test_answer_key_must_be_outside_the_output(tmp_path: Path, root: Path) -> None:
    output = tmp_path / "instances"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("keep")
    with pytest.raises(MaterializationError, match="answer key"):
        materialize(root=root, output=output, force=True, answer_key=output / "key.json")
    assert marker.read_text() == "keep", "a rejected run must not delete an existing output"
