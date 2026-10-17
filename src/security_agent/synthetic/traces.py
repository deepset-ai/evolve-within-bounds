# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
`read_reasoning` for the optimizer: what did the agent do on a TRAINING pair?

For the vulnerable repository or its safe twin, and for one of the draft's runs, this returns the agent's conversation
from the scan record: its reasoning, tool calls and results, and text, step by step, shortened to fit `MAX_CHARS`.
Steps that mention a planted file get three times the room of the others. Also: why the agent stopped, and what it
reported in the planted files.

Only training pairs are accepted. Code quoted in the conversation is passed to `on_shown`, so the leakage check also
refuses it in a candidate. Reads per turn are capped (`MAX_READS`): one read is a few thousand tokens of the
optimizer's context.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import Any

from security_agent.synthetic.bench.adapters import load_benchmark
from security_agent.synthetic.bench.pairs import load_pairs, pair_targets

MAX_CHARS = 12_000
MAX_READS = 8
HEAD, TAIL, WINDOW = 1_500, 2_500, 500
CODE_SPAN = re.compile(r"`([^`\n]{12,240})`")
NUMBERED = re.compile(r"^\s*\d+ \| (.+)$", re.M)  # read_file's output lines


def shorten(text: str, budget: int, needles: list[str]) -> str:
    """`text` within `budget` characters: the head, the passages around `needles`, and the tail."""
    if len(text) <= budget:
        return text
    spans = [(0, min(HEAD, budget // 4)), (max(0, len(text) - min(TAIL, budget // 3)), len(text))]
    room = budget - sum(b - a for a, b in spans)
    for needle in needles:
        for m in re.finditer(re.escape(needle), text):
            if room <= 0:
                break
            a, b = max(0, m.start() - WINDOW), min(len(text), m.end() + WINDOW)
            spans.append((a, b))
            room -= b - a
    merged: list[list[int]] = []
    for a, b in sorted(spans):
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return "\n[...]\n".join(text[a:b] for a, b in merged)


class ReasoningReader:
    """
    `read_reasoning` on training pairs.

    :param train: the training pairs, `{benchmark: [pair_id, ...]}`.
    :param record: `(benchmark, instance_id)` -> the draft's record of that instance in its latest measurement, or None.
    :param on_shown: receives leakage material, `{"code": [...]}`.
    """

    def __init__(
        self,
        train: dict[str, list[str]],
        record: Callable[[str, str], dict | None],
        on_shown: Callable[[dict[str, list[str]]], None] | None = None,
        bench_loader: Callable = load_benchmark,
    ) -> None:
        self.train = {name: set(ids) for name, ids in train.items()}
        self.record = record
        self.on_shown = on_shown
        self.bench_loader = bench_loader
        self._pairs: dict[str, dict[str, dict]] = {}

    def _pair(self, benchmark: str, pair_id: str) -> dict:
        if benchmark not in self._pairs:
            self._pairs[benchmark] = load_pairs(self.bench_loader(benchmark))
        return self._pairs[benchmark][pair_id]

    def __call__(self, example: str, side: str = "vulnerable", run: int = 1) -> str:  # noqa: ARG002 - one run per candidate
        """What the agent did on one member of a training pair."""
        benchmark, _, pair_id = example.strip().partition("/")
        if pair_id not in self.train.get(benchmark, set()):
            return json.dumps(
                {
                    "ok": False,
                    "error": f"'{example}' is not a training pair key; use one from the digests or the list of "
                    "training pair keys",
                }
            )
        if side not in ("vulnerable", "safe_twin"):
            return json.dumps({"ok": False, "error": "side must be 'vulnerable' or 'safe_twin'"})
        pair = self._pair(benchmark, pair_id)
        instance_id = pair["mutant_instance_id" if side == "vulnerable" else "baseline_instance_id"]
        record = self.record(benchmark, instance_id)
        if not record:
            return json.dumps({"ok": False, "error": "no saved record of the draft for this pair"})
        planted = {
            t["path"]: (
                t["mutant_line_start" if side == "vulnerable" else "baseline_line_start"],
                t["mutant_line_end" if side == "vulnerable" else "baseline_line_end"],
            )
            for t in pair_targets(pair)
        }
        out: dict[str, Any] = {
            "ok": True,
            "pair": example,
            "side": side,
            "planted": [{"path": p, "lines": list(lines)} for p, lines in planted.items()],
        }
        agent = record.get("agent") or {}
        names = [PurePosixPath(p).name for p in planted]
        steps = agent.get("trajectory", [])
        out.update(
            stop=agent.get("stop"),
            steps=agent.get("steps"),
            findings_reported=len(agent.get("reported", [])),
            reported_in_planted_files=[r for r in agent.get("reported", []) if r.get("path") in planted][:8],
            tool_errors=[c for c in agent.get("tool_calls", []) if not c.get("ok")][:5],
        )
        if not steps:
            out["note"] = "the run kept no conversation (the agent failed before its first answer)"
            return json.dumps(out, indent=1)
        room = max(150, MAX_CHARS // max(1, len(steps)))
        shown_code: list[str] = []
        out["conversation"] = []
        for i, step in enumerate(steps):
            budget = room * (3 if any(n in json.dumps(step) for n in names) else 1)
            item: dict[str, Any] = {"step": i, "role": step.get("role")}
            if step.get("reasoning"):
                item["reasoning"] = shorten(step["reasoning"], budget, names)
                shown_code += CODE_SPAN.findall(item["reasoning"])
            if step.get("text"):
                item["text"] = shorten(step["text"], budget if i else min(budget, 600), names)
            if step.get("calls"):
                item["calls"] = step["calls"]
            if step.get("results"):
                item["results"] = [
                    {
                        "tool": r.get("tool"),
                        "error": r.get("error"),
                        "result": shorten(str(r.get("result", "")), budget, names),
                    }
                    for r in step["results"]
                ]
                shown_code += [line for r in item["results"] for line in NUMBERED.findall(r["result"])]
            out["conversation"].append(item)
        if self.on_shown and shown_code:
            self.on_shown({"code": shown_code})
        return json.dumps(out, indent=1)
