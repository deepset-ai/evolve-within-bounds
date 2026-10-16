from __future__ import annotations

import json
from pathlib import Path

from haystack_component_vulnerability_benchmark.catalog import primary_target
from haystack_component_vulnerability_benchmark.score import score_predictions


def _single(tmp_path: Path, pairs: list[dict], pair: dict, findings: list[dict]) -> Path:
    path = tmp_path / "p.jsonl"
    rows = []
    for other in pairs:
        rows.append({"instance_id": other["baseline_instance_id"], "findings": []})
        rows.append(
            {
                "instance_id": other["mutant_instance_id"],
                "findings": findings if other["pair_id"] == pair["pair_id"] else [],
            }
        )
        if other.get("placebo_instance_id"):
            rows.append({"instance_id": other["placebo_instance_id"], "findings": []})
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def _row(report: dict, pair: dict) -> dict:
    return next(r for r in report["pair_results"] if r["pair_id"] == pair["pair_id"])


def test_sink_report_scores(tmp_path: Path, root: Path, pairs: list[dict], multi_file_pair) -> None:
    sink = primary_target(multi_file_pair)
    predictions = _single(
        tmp_path,
        pairs,
        multi_file_pair,
        [
            {
                "path": sink["path"],
                "line_start": sink["mutant_line_start"],
                "line_end": sink["mutant_line_end"],
                "cwe": multi_file_pair["cwe"],
            }
        ],
    )
    row = _row(score_predictions(root=root, prediction_path=predictions), multi_file_pair)
    assert row["pair_correct"] is True


def test_source_only_report_does_not_score(
    tmp_path: Path, root: Path, pairs: list[dict], multi_file_pair
) -> None:
    """Reporting the taint source without the sink is not finding the vulnerability,
    but it is worth observing, so it surfaces as a per-pair diagnostic only."""
    source = next(t for t in multi_file_pair["targets"] if t["role"] == "source")
    predictions = _single(
        tmp_path,
        pairs,
        multi_file_pair,
        [
            {
                "path": source["path"],
                "line_start": source["mutant_line_start"],
                "line_end": source["mutant_line_end"],
                "cwe": multi_file_pair["cwe"],
            }
        ],
    )
    row = _row(score_predictions(root=root, prediction_path=predictions), multi_file_pair)
    assert row["pair_correct"] is False
    assert row["mutant_detected_any_target"] is True
    assert row["multi_file"] is True


def test_single_file_pairs_are_unaffected(
    tmp_path: Path, root: Path, pairs: list[dict], write_predictions
) -> None:
    predictions = tmp_path / "all.jsonl"
    write_predictions(predictions, pairs)
    report = score_predictions(root=root, prediction_path=predictions)
    for row in report["pair_results"]:
        if not row["multi_file"]:
            assert row["pair_correct"] is True
