from __future__ import annotations

from pathlib import Path

from haystack_component_vulnerability_benchmark.score import score_predictions


def test_flag_every_diff_agent_is_caught(
    tmp_path: Path, root: Path, pairs: list[dict], write_predictions
) -> None:
    """The point of the whole placebo design.

    An agent that reports a finding at every changed span scores a perfect strict
    paired accuracy -- indistinguishable from a real detector under the planted
    metrics alone -- yet alarms on every benign control.
    """
    honest = tmp_path / "honest.jsonl"
    degenerate = tmp_path / "degenerate.jsonl"
    write_predictions(honest, pairs, placebo_alarm=False)
    write_predictions(degenerate, pairs, placebo_alarm=True)

    good = score_predictions(root=root, prediction_path=honest)
    bad = score_predictions(root=root, prediction_path=degenerate)

    assert good["strict_paired_accuracy"] == bad["strict_paired_accuracy"] == 1.0
    assert good["placebo"]["change_induced_false_alarm_rate"] == 0.0
    assert bad["placebo"]["change_induced_false_alarm_rate"] == 1.0
    assert good["discrimination_index"] == 1.0
    assert bad["discrimination_index"] == 0.0


def test_placebo_controls_do_not_enter_the_planted_denominator(
    tmp_path: Path, root: Path, pairs: list[dict], write_predictions
) -> None:
    predictions = tmp_path / "p.jsonl"
    write_predictions(predictions, pairs, placebo_alarm=True)
    report = score_predictions(root=root, prediction_path=predictions)
    assert report["planted_pairs"] == len(pairs)
    assert report["placebo"]["controls"] == sum(
        1 for pair in pairs if pair.get("placebo_instance_id")
    )
    for values in report["by_recipe"].values():
        assert values["pairs"] >= 1
    benign_recipes = {p.get("placebo_recipe_id") for p in pairs if p.get("placebo_recipe_id")}
    assert not (benign_recipes & set(report["by_recipe"]))


def test_discrimination_accuracy_tracks_the_triplets(
    tmp_path: Path, root: Path, pairs: list[dict], write_predictions
) -> None:
    honest = tmp_path / "honest.jsonl"
    write_predictions(honest, pairs, placebo_alarm=False)
    report = score_predictions(root=root, prediction_path=honest)
    assert report["placebo"]["discrimination_accuracy"] == 1.0
    discriminated = [r for r in report["pair_results"] if "discriminated" in r]
    assert len(discriminated) == report["placebo"]["controls"]
