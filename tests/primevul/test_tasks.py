# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json

import pytest
from pv_helpers import write_benchmark

from security_agent.primevul.tasks import load_tasks, pair_up, read_tasks


def test_tasks_carry_the_rendered_question_and_the_labels(tmp_path):
    tasks = read_tasks(write_benchmark(tmp_path / "b.jsonl"))
    first = tasks[0]
    assert first.question.startswith("Analyze the following c function for security vulnerabilities")
    assert "```c\nint f0(char *s)" in first.question
    assert first.gold["is_vulnerable"] is True
    assert first.gold["pair_id"] == "train-0"
    assert {t.split for t in tasks} == {"train", "val", "holdout"}


def test_the_first_pairs_in_file_order(tmp_path):
    path = write_benchmark(tmp_path / "b.jsonl", pairs_per_split=3)
    tasks = load_tasks(path, "holdout", max_pairs=2)
    assert [t.id for t in tasks] == ["holdout-0-v", "holdout-0-f", "holdout-1-v", "holdout-1-f"]
    assert sorted(pair_up(tasks)) == ["holdout-0", "holdout-1"]
    assert len(load_tasks(path, "holdout")) == 6


def test_a_pair_needs_both_members(tmp_path):
    tasks = load_tasks(write_benchmark(tmp_path / "b.jsonl"), "train")
    assert sorted(pair_up(tasks[1:])) == ["train-1"]


def test_bad_split_and_missing_file(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"id": 1, "code": "", "gold_is_vulnerable": True, "split": "test"}) + "\n")
    with pytest.raises(ValueError, match="split must be one of"):
        read_tasks(bad)
    with pytest.raises(FileNotFoundError, match="hatch run primevul:build"):
        read_tasks(tmp_path / "missing.jsonl")
