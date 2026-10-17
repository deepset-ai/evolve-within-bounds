# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json

import pytest

from security_agent.optimize import splits
from security_agent.synthetic.config import REPO_ROOT
from security_agent.synthetic.task import split as synthetic_split


def test_the_split_is_by_repository_and_disjoint():
    split = synthetic_split()
    assert {role: len(by_bench["hvbench"]) for role, by_bench in split.items()} == {"train": 25, "val": 13, "test": 12}
    rows = {
        json.loads(line)["pair_id"]: json.loads(line)
        for line in (REPO_ROOT / "data/synthetic-components/data/pairs.jsonl").read_text().splitlines()
        if line.strip()
    }
    role_of = {p: role for role, by_bench in split.items() for p in by_bench["hvbench"]}
    assert set(role_of) == set(rows)
    repos: dict[str, set] = {}
    for pair_id, row in rows.items():
        repos.setdefault(row["repository"], set()).add(role_of[pair_id])
    assert all(len(roles) == 1 for roles in repos.values())


def test_subsample_is_deterministic():
    train = {"a": [f"p{i}" for i in range(30)], "b": [f"q{i}" for i in range(5)]}
    picked = splits.subsample(train, 12, 20261013)
    assert (
        len(picked["a"]) == 12 and picked["b"] == sorted(train["b"]) and picked == splits.subsample(train, 12, 20261013)
    )
    assert picked != splits.subsample(train, 12, 1)


def test_check_disjoint_catches_overlap(tmp_path):
    (tmp_path / "split.json").write_text(
        json.dumps({"train": {"a": ["p1", "p2"]}, "val": {"a": ["p3"]}, "test": {"a": ["p2"]}})
    )
    with pytest.raises(ValueError, match="p2 is in both train and test"):
        splits.load_split(tmp_path / "split.json")
