# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import pytest
from pv_helpers import pair, verdict

from security_agent.primevul.scoring import aggregate, headline, score_pair


@pytest.mark.parametrize(
    "on_vulnerable, on_fixed, expected",
    [
        (True, False, "correct"),
        (True, True, "missed_fix"),
        (False, False, "missed_bug"),
        (False, True, "inverted"),
        (None, False, "parse_error"),
        (True, None, "parse_error"),
    ],
)
def test_pair_labels(on_vulnerable, on_fixed, expected):
    members = pair("p")
    verdicts = {"p-v": verdict(on_vulnerable), "p-f": verdict(on_fixed)}
    result = score_pair("p", members, verdicts)
    assert result.label == expected
    assert result.gold_cwe == "CWE-787"


def test_metrics():
    outcomes = {
        "a": (True, False),  # correct
        "b": (True, False),  # correct
        "c": (True, True),  # missed_fix
        "d": (False, True),  # inverted
        "e": (False, False),  # missed_bug
        "f": (None, True),  # parse_error
    }
    pairs = {pid: pair(pid) for pid in outcomes}
    verdicts = {}
    for pid, (v, f) in outcomes.items():
        verdicts[f"{pid}-v"] = verdict(v)
        verdicts[f"{pid}-f"] = verdict(f)
    m = aggregate(pairs, verdicts)
    assert m.counts == {"correct": 2, "missed_fix": 1, "missed_bug": 1, "inverted": 1, "parse_error": 1}
    assert m.paired_accuracy == pytest.approx(2 / 6)
    assert m.split_rate == pytest.approx(3 / 6)
    assert m.right_way_rate == pytest.approx(2 / 3)
    # Per function: patched members called vulnerable (c, d, f) of the six with a verdict.
    assert m.false_positive_rate == pytest.approx(3 / 6)
    # Per pair: missed_fix + inverted of the five pairs with both verdicts.
    assert m.pair_false_positive_rate == pytest.approx(2 / 5)
    assert m.parse_error_rate == pytest.approx(1 / 12)
    assert "paired 0.333 (2/6)" in headline(m)
    assert "pairs" not in m.to_dict(with_pairs=False)
    assert [p["label"] for p in m.to_dict()["pairs"]] == [
        "correct",
        "correct",
        "missed_fix",
        "inverted",
        "missed_bug",
        "parse_error",
    ]


def test_a_missing_verdict_counts_as_a_parse_error():
    m = aggregate({"a": pair("a")}, {})
    assert m.counts["parse_error"] == 1
    assert m.paired_accuracy == 0.0
    assert m.pair_false_positive_rate == 0.0
