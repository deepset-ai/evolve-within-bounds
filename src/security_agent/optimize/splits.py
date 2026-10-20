# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Which pairs belong to train, validation and test: a split file, `{role: {benchmark: [pair_id, ...]}}`.

A split should be by repository (or project): every pair of one goes to the same role, so near-identical code never
sits on both sides. The loop only reads `train`; validation picks among the candidates afterwards, and test is looked
at once at the end.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

ROLES = ("train", "val", "test")


def load_split(path: Path) -> dict[str, dict[str, list[str]]]:
    """Read a split file and check that no pair has two roles."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    split = {role: {bench: list(ids) for bench, ids in data[role].items()} for role in ROLES}
    check_disjoint(split)
    return split


def pairs(role: str, split: dict[str, dict[str, list[str]]]) -> dict[str, list[str]]:
    """The pairs of one role, `{benchmark: [pair_id, ...]}`."""
    if role not in split:
        raise KeyError(f"no split role '{role}'; roles: {', '.join(ROLES)}")
    return split[role]


def subsample(selected: dict[str, list[str]], per_benchmark: int, seed: int | str) -> dict[str, list[str]]:
    """The same `per_benchmark` pairs of each benchmark every time."""
    out = {}
    for name, ids in sorted(selected.items()):
        shuffled = sorted(ids)
        random.Random(f"{seed}:subsample:{name}").shuffle(shuffled)
        out[name] = sorted(shuffled[:per_benchmark])
    return out


def check_disjoint(split: dict[str, dict[str, list[str]]]) -> None:
    """Raise if a pair has two roles."""
    for benchmark in {b for by_bench in split.values() for b in by_bench}:
        seen: dict[str, str] = {}
        for role, by_bench in split.items():
            for pair_id in by_bench.get(benchmark, []):
                if pair_id in seen:
                    raise ValueError(f"{benchmark} {pair_id} is in both {seen[pair_id]} and {role}")
                seen[pair_id] = role
