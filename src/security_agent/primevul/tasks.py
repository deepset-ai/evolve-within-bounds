# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The benchmark file, one task per function, and the pairs.

A record of the file (built by `hatch run primevul:build`) has `id`, `code`, `lang`, `gold_is_vulnerable`, `gold_cwe`,
`pair_id` and `split` (train, val or holdout). A pair is a vulnerable function and its patched twin; the agent judges
each alone, and the pair counts as right only when it calls the vulnerable one vulnerable and the patched one benign.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_FILE = REPO_ROOT / "data" / "primevul" / "build" / "primevul-loop.jsonl"
SPLITS = ("train", "val", "holdout")

# The user message: the only thing that varies per task. The agent's instructions are in its system prompt.
INPUT_TEMPLATE = """Analyze the following {lang} function for security \
vulnerabilities and respond with your triage verdict as JSON.

```{lang}
{code}
```"""


@dataclass(frozen=True)
class Task:
    """One function: the user message the agent gets, and the labels only the scorer reads."""

    id: str
    question: str
    split: str
    gold: dict[str, Any] = field(default_factory=dict)


def read_tasks(path: Path) -> list[Task]:
    """Every record of a benchmark file as a task."""
    if not path.exists():
        raise FileNotFoundError(f"no benchmark file at {path}; build it with `hatch run primevul:build`")
    tasks = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        record = json.loads(line)
        split = record.get("split", "train")
        if split not in SPLITS:
            raise ValueError(f"{path}:{line_no}: split must be one of {', '.join(SPLITS)}")
        lang = record.get("lang", "c")
        tasks.append(
            Task(
                id=str(record["id"]),
                question=INPUT_TEMPLATE.format(lang=lang, code=record["code"]),
                split=split,
                gold={
                    "is_vulnerable": bool(record["gold_is_vulnerable"]),
                    "cwe": record.get("gold_cwe"),
                    "pair_id": record.get("pair_id"),
                    "code": record["code"],
                    "lang": lang,
                },
            )
        )
    return tasks


def load_tasks(path: Path, split: str, max_pairs: int | None = None) -> list[Task]:
    """The tasks of one split; with `max_pairs`, those of its first N pairs in file order."""
    tasks = [t for t in read_tasks(path) if t.split == split]
    if not max_pairs:
        return tasks
    first: list[str] = []
    for task in tasks:
        pair_id = str(task.gold.get("pair_id"))
        if pair_id not in first:
            first.append(pair_id)
    chosen = set(first[:max_pairs])
    return [t for t in tasks if str(t.gold.get("pair_id")) in chosen]


def pair_up(tasks: list[Task]) -> dict[str, dict[str, Task]]:
    """`{pair_id: {"vulnerable": task, "fixed": task}}` for every pair with both members."""
    pairs: dict[str, dict[str, Task]] = {}
    for task in tasks:
        slot = "vulnerable" if task.gold.get("is_vulnerable") else "fixed"
        pairs.setdefault(str(task.gold.get("pair_id")), {})[slot] = task
    return {pid: members for pid, members in pairs.items() if "vulnerable" in members and "fixed" in members}
