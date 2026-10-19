# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Benchmark pairs as the harness reads them, from the benchmark's `data/pairs.jsonl`.

Each pair lists its marked lines in `targets`: a path, the mutant's and the baseline's line spans, and a `role`. The
scorer uses the `sink` target. `pair_targets` returns them in one shape for digests, examples and the leakage check.
`summarize_pairs` reduces the scorer's per-pair results to the pairs a run scanned.
"""

from __future__ import annotations

import json
from typing import Any

from security_agent.synthetic.bench.adapters import load_benchmark


def is_planted(pair: dict[str, Any]) -> bool:
    """Is the pair a planted one (a vulnerable repository and its safe twin)?"""
    return pair.get("pair_class", "planted") == "planted" and pair.get("planted", True) is not False


def load_pairs(benchmark: Any) -> dict[str, dict[str, Any]]:
    """pair_id -> pair row. `benchmark` is a `Benchmark` or its name."""
    bench = load_benchmark(benchmark) if isinstance(benchmark, str) else benchmark
    path = bench.root / "data" / "pairs.jsonl"
    rows = (json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    return {row["pair_id"]: row for row in rows}


def pair_targets(pair: dict[str, Any]) -> list[dict[str, Any]]:
    """The marked target(s) of a pair as `{path, role, mutant_line_*, baseline_line_*}`; sink targets first."""
    targets = pair.get("targets") or []
    return [t for t in targets if t.get("role", "sink") == "sink"] or list(targets)


def summarize_pairs(pair_results: list[dict[str, Any]], pair_ids: set[str]) -> dict[str, Any]:
    """The paired metrics over `pair_ids`, from the scorer's `pair_results` (its scores cover the whole benchmark)."""
    rows = [r for r in pair_results if r["pair_id"] in pair_ids]

    def mean(key: str) -> float | None:
        return round(sum(1 for r in rows if r[key]) / len(rows), 4) if rows else None

    return {
        "pairs": len(rows),
        "paired_localization_accuracy": mean("pair_localized_correct"),
        "strict_paired_accuracy": mean("pair_correct"),
        "mutant_localization_recall": mean("mutant_localized"),
        "baseline_mapped_localization_false_alarm_rate": mean("baseline_mapped_localization_alarm"),
        "pairs_right": sorted(r["pair_id"] for r in rows if r["pair_localized_correct"]),
    }
