# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
A label per pair, and the metrics.

Labels: `correct` (the vulnerable member called vulnerable, the patched one benign), `missed_fix` (both vulnerable),
`missed_bug` (both benign), `inverted` (the wrong way round) and `parse_error` (a member without a verdict).

Metrics: paired accuracy, and its two factors: the split rate (the members got different verdicts) and the right-way
rate (of those, the right way round). A change that only makes the two members' errors less alike raises the first
without the second. Two false positive rates: per function (patched functions called vulnerable, of those with a
verdict) and per pair (pairs whose patched member was called vulnerable, of the pairs with both verdicts).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from security_agent.primevul.tasks import Task
from security_agent.primevul.verdict import normalize_cwe

PAIR_LABELS = ("correct", "missed_fix", "missed_bug", "inverted", "parse_error")


def label(verdict: dict[str, Any] | None) -> bool | None:
    """True for vulnerable, False for benign, None for no verdict."""
    if not verdict or verdict.get("parse_error"):
        return None
    return bool(verdict.get("is_vulnerable"))


@dataclass
class PairResult:
    """One pair's label and the verdicts on its two members."""

    pair_id: str
    label: str
    vulnerable_task: str
    fixed_task: str
    vulnerable_verdict: dict[str, Any] | None
    fixed_verdict: dict[str, Any] | None
    gold_cwe: str | None

    def to_dict(self) -> dict[str, Any]:
        """The pair as JSON."""
        return {
            "pair_id": self.pair_id,
            "label": self.label,
            "gold_cwe": self.gold_cwe,
            "vulnerable": {"task": self.vulnerable_task, "verdict": self.vulnerable_verdict},
            "fixed": {"task": self.fixed_task, "verdict": self.fixed_verdict},
        }


def score_pair(pair_id: str, members: dict[str, Task], verdicts: dict[str, dict[str, Any]]) -> PairResult:
    """Label one pair from the verdicts on its members."""
    v_task, f_task = members["vulnerable"], members["fixed"]
    v_verdict, f_verdict = verdicts.get(v_task.id), verdicts.get(f_task.id)
    lv, lf = label(v_verdict), label(f_verdict)
    if lv is None or lf is None:
        name = "parse_error"
    elif lv and not lf:
        name = "correct"
    elif lv and lf:
        name = "missed_fix"
    elif not lv and not lf:
        name = "missed_bug"
    else:
        name = "inverted"
    return PairResult(pair_id, name, v_task.id, f_task.id, v_verdict, f_verdict, normalize_cwe(v_task.gold.get("cwe")))


@dataclass
class PairMetrics:
    """The pair labels of one measurement, and what follows from them."""

    pairs: list[PairResult]
    false_positive_rate: float
    parse_error_rate: float
    seconds: float = 0.0
    median_task_seconds: float = 0.0

    @property
    def n(self) -> int:
        """Pairs."""
        return len(self.pairs)

    @property
    def counts(self) -> dict[str, int]:
        """Pairs per label."""
        return {name: sum(1 for p in self.pairs if p.label == name) for name in PAIR_LABELS}

    @property
    def paired_accuracy(self) -> float:
        """Pairs right, of all pairs."""
        return self.counts["correct"] / self.n if self.n else 0.0

    @property
    def split_rate(self) -> float:
        """Pairs whose members got different verdicts, of all pairs."""
        return (self.counts["correct"] + self.counts["inverted"]) / self.n if self.n else 0.0

    @property
    def right_way_rate(self) -> float:
        """Of the pairs whose members got different verdicts, those the right way round."""
        split = self.counts["correct"] + self.counts["inverted"]
        return self.counts["correct"] / split if split else 0.0

    @property
    def pair_false_positive_rate(self) -> float:
        """Pairs whose patched member was called vulnerable, of the pairs with both verdicts."""
        c = self.counts
        judged = self.n - c["parse_error"]
        return (c["missed_fix"] + c["inverted"]) / judged if judged else 0.0

    def to_dict(self, *, with_pairs: bool = True) -> dict[str, Any]:
        """The metrics as JSON; with `with_pairs`, each pair's label and verdicts too."""
        out: dict[str, Any] = {
            "n_pairs": self.n,
            "paired_accuracy": round(self.paired_accuracy, 4),
            "split_rate": round(self.split_rate, 4),
            "right_way_rate": round(self.right_way_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "pair_false_positive_rate": round(self.pair_false_positive_rate, 4),
            "parse_error_rate": round(self.parse_error_rate, 4),
            "counts": self.counts,
            "seconds": round(self.seconds),
            "median_task_seconds": round(self.median_task_seconds),
        }
        if with_pairs:
            out["pairs"] = [p.to_dict() for p in self.pairs]
        return out


def aggregate(
    pairs: dict[str, dict[str, Task]], verdicts: dict[str, dict[str, Any]], seconds: float = 0.0
) -> PairMetrics:
    """Score every pair."""
    results = [score_pair(pid, members, verdicts) for pid, members in sorted(pairs.items())]
    fixed = [members["fixed"].id for members in pairs.values()]
    fp = sum(1 for t in fixed if label(verdicts.get(t)) is True)
    tn = sum(1 for t in fixed if label(verdicts.get(t)) is False)
    missing = sum(
        1
        for members in pairs.values()
        for slot in ("vulnerable", "fixed")
        if label(verdicts.get(members[slot].id)) is None
    )
    return PairMetrics(
        results,
        false_positive_rate=fp / (fp + tn) if fp + tn else 0.0,
        parse_error_rate=missing / (2 * len(pairs)) if pairs else 0.0,
        seconds=seconds,
    )


def headline(m: PairMetrics) -> str:
    """One line: paired accuracy and its factors, the false positive rates, parse errors, the failure labels."""
    c = m.counts
    return (
        f"paired {m.paired_accuracy:.3f} ({c['correct']}/{m.n}) | split {m.split_rate:.2f} x right-way "
        f"{m.right_way_rate:.2f} | false positives {m.false_positive_rate:.2f} (pairs "
        f"{m.pair_false_positive_rate:.2f}) | parse errors {m.parse_error_rate:.2f} | "
        f"missed_fix {c['missed_fix']} missed_bug {c['missed_bug']} inverted {c['inverted']}"
        + (f" | median {m.median_task_seconds:.0f}s/task" if m.median_task_seconds else "")
    )
