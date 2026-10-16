from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import UNRELATED_CWE

from haystack_component_vulnerability_benchmark.score import ScoreError, score_predictions


def test_perfect_predictions(
    tmp_path: Path, root: Path, pairs: list[dict], write_predictions
) -> None:
    predictions = tmp_path / "p.jsonl"
    write_predictions(predictions, pairs)
    report = score_predictions(root=root, prediction_path=predictions)
    assert report["strict_paired_accuracy"] == 1.0
    assert report["mutant_recall"] == 1.0
    assert report["baseline_mapped_false_alarm_rate"] == 0.0
    assert report["paired_localization_accuracy"] == 1.0
    assert report["planted_pairs"] == len(pairs)
    assert report["primary_metric"] == "strict_paired_accuracy"


def test_silent_agent_scores_zero(
    tmp_path: Path, root: Path, pairs: list[dict], write_predictions
) -> None:
    predictions = tmp_path / "p.jsonl"
    write_predictions(predictions, pairs, detect=False)
    report = score_predictions(root=root, prediction_path=predictions)
    assert report["strict_paired_accuracy"] == 0.0
    assert report["placebo"]["change_induced_false_alarm_rate"] == 0.0


def test_baseline_alarm_fails_its_pair(
    tmp_path: Path, root: Path, pairs: list[dict], write_predictions
) -> None:
    predictions = tmp_path / "p.jsonl"
    write_predictions(predictions, pairs, baseline_alarm=True)
    n = len(pairs)
    report = score_predictions(root=root, prediction_path=predictions)
    assert report["strict_paired_accuracy"] == (n - 1) / n
    assert report["baseline_mapped_false_alarm_rate"] == 1 / n


def test_wrong_cwe_scores_localization_but_not_strict(
    tmp_path: Path, root: Path, pairs: list[dict], write_predictions
) -> None:
    predictions = tmp_path / "p.jsonl"
    write_predictions(predictions, pairs, cwe_override=UNRELATED_CWE)
    report = score_predictions(root=root, prediction_path=predictions)
    assert report["strict_paired_accuracy"] == 0.0
    assert report["paired_localization_accuracy"] == 1.0


def test_missing_instances_are_rejected(tmp_path: Path, root: Path) -> None:
    predictions = tmp_path / "p.jsonl"
    predictions.write_text("", encoding="utf-8")
    with pytest.raises(ScoreError, match="omit"):
        score_predictions(root=root, prediction_path=predictions)


def test_placebo_instances_are_required(
    tmp_path: Path, root: Path, pairs: list[dict], write_predictions
) -> None:
    predictions = tmp_path / "p.jsonl"
    write_predictions(predictions, pairs)
    kept = [
        line
        for line in predictions.read_text().splitlines()
        if not any(json.loads(line)["instance_id"] == p.get("placebo_instance_id") for p in pairs)
    ]
    predictions.write_text("\n".join(kept) + "\n", encoding="utf-8")
    with pytest.raises(ScoreError, match="omit"):
        score_predictions(root=root, prediction_path=predictions)


@pytest.mark.parametrize(
    "record",
    [{"instance_id": "instance-unknown"}, {"instance_id": "instance-unknown", "findings": ["x"]}],
)
def test_malformed_records_are_rejected(tmp_path: Path, root: Path, record: dict) -> None:
    predictions = tmp_path / "p.jsonl"
    predictions.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(ScoreError):
        score_predictions(root=root, prediction_path=predictions, require_complete=False)
