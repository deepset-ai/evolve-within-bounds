# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
PrimeVul as a NeMo Gym environment: the parts that do not need Gym installed.

The environment itself is in gym/: a resources server that scores rollouts, and an agent server that runs our agent
files through Gym's Haystack harness. Both import this module, so the rollouts are scored exactly as
`security-agent primevul run` scores, and this module is tested without Gym.

- `task_row`, `export`: a benchmark task as a Gym row. The user message is the one our runner sends; the labels are
  top-level task fields the resources server reads.
- `score`: one rollout. Its reward is 1.0 when the function's verdict is right, so Gym's mean reward is per-function
  accuracy.
- `pair_metrics`: the pairs of one repeat: paired accuracy (the benchmark's number), its factors, the false positive
  rates and the parse-error rate. `mean_over_repeats`: the same, averaged over repeats; pooling them would require a
  pair's functions to be right in every repeat.
- `harness_pipeline`: an agent file as the pipeline Gym's harness runs. Only the chat generator changes: Gym's
  generator calls Gym's model server, which adds the thinking budget to every request. The prompt, the tool and the
  budgets stay as they are.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from security_agent.primevul.scoring import aggregate
from security_agent.primevul.tasks import Task, load_tasks, pair_up
from security_agent.primevul.verdict import normalize_cwe, parse_verdict

GYM_GENERATOR = "responses_api_agents.haystack_agent.chat_generator.NeMoGymResponsesChatGenerator"
REPEAT_KEY = "_ng_rollout_index"  # Gym's repeat number on each verified row
MODEL_SERVER = "policy_model"


def task_row(task: Task) -> dict[str, Any]:
    """One function as a Gym row."""
    return {
        "responses_create_params": {"input": [{"role": "user", "content": task.question}]},
        "task_id": task.id,
        "pair_id": str(task.gold.get("pair_id")),
        "gold_is_vulnerable": bool(task.gold.get("is_vulnerable")),
        "gold_cwe": task.gold.get("cwe"),
    }


def export(data: Path, split: str, out: Path, max_pairs: int | None = None) -> int:
    """Write the rows of one split (the first `max_pairs` pairs) to `out`; returns how many."""
    tasks = load_tasks(data, split, max_pairs)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for task in tasks:
            handle.write(json.dumps(task_row(task)) + "\n")
    return len(tasks)


def final_text(response: Any) -> str:
    """The agent's last assistant message in a Responses-API response; tool calls and reasoning are skipped."""
    output = (response or {}).get("output") or [] if isinstance(response, dict) else []
    for item in reversed(output):
        if not isinstance(item, dict) or item.get("type") not in (None, "message"):
            continue
        if item.get("role") not in (None, "assistant"):
            continue
        content = item.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            texts = [part.get("text", "") for part in content if isinstance(part, dict) and part.get("text")]
            if texts:
                return "".join(texts)
    return ""


def score(response: Any, row: dict[str, Any]) -> dict[str, Any]:
    """One rollout against its row's labels: the reward and what the pair metrics need."""
    verdict = parse_verdict(final_text(response))
    predicted = None if verdict["parse_error"] else bool(verdict["is_vulnerable"])
    gold = bool(row.get("gold_is_vulnerable"))
    correct = predicted is not None and predicted == gold
    gold_cwe = normalize_cwe(row.get("gold_cwe"))
    return {
        "reward": float(correct),
        "correct": correct,
        "parse_error": bool(verdict["parse_error"]),
        "pred_is_vulnerable": predicted,
        "pred_cwe": verdict.get("cwe"),
        "cwe_correct": bool(gold and correct and verdict.get("cwe") == gold_cwe),
    }


def pair_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The pairs of one repeat, from scored rows (`task_id`, `pair_id`, the labels and the prediction)."""
    tasks = [
        Task(
            id=str(row.get("task_id")),
            question="",
            split="",
            gold={
                "is_vulnerable": bool(row.get("gold_is_vulnerable")),
                "cwe": row.get("gold_cwe"),
                "pair_id": row.get("pair_id"),
            },
        )
        for row in rows
    ]
    verdicts = {
        str(row.get("task_id")): {"parse_error": True}
        if row.get("parse_error") or row.get("pred_is_vulnerable") is None
        else {"is_vulnerable": bool(row["pred_is_vulnerable"]), "cwe": row.get("pred_cwe"), "parse_error": False}
        for row in rows
    }
    pairs = pair_up(tasks)
    if not pairs:
        return {}
    m = aggregate(pairs, verdicts)
    return {
        "paired_accuracy": m.paired_accuracy,
        "split_rate": m.split_rate,
        "right_way_rate": m.right_way_rate,
        "false_positive_rate": m.false_positive_rate,
        "pair_false_positive_rate": m.pair_false_positive_rate,
        "parse_error_rate": m.parse_error_rate,
        "pairs": m.n,
        **{f"pairs_{name}": count for name, count in m.counts.items()},
    }


def mean_over_repeats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """`pair_metrics` of each repeat (`REPEAT_KEY`), averaged."""
    by_repeat: dict[Any, list[dict[str, Any]]] = {}
    for row in rows:
        by_repeat.setdefault(row.get(REPEAT_KEY, 0), []).append(row)
    per_repeat = [m for m in (pair_metrics(group) for group in by_repeat.values()) if m]
    if not per_repeat:
        return {}
    return {key: sum(m[key] for m in per_repeat) / len(per_repeat) for key in per_repeat[0]}


def harness_pipeline(agent: dict[str, Any], server_name: str = MODEL_SERVER) -> dict[str, Any]:
    """An agent file as the one-component pipeline Gym's Haystack harness runs."""
    agent = copy.deepcopy(agent)
    params = agent["init_parameters"]
    generator = params["chat_generator"]["init_parameters"]
    kwargs = dict(generator.get("generation_kwargs") or {})
    responses_kwargs: dict[str, Any] = {}
    if "max_tokens" in kwargs:
        responses_kwargs["max_output_tokens"] = kwargs.pop("max_tokens")
    if "temperature" in kwargs:
        responses_kwargs["temperature"] = kwargs.pop("temperature")
    kwargs.pop("extra_body", None)  # the thinking budget is the model server's (gym/.../configs/primevul.yaml)
    if kwargs:
        raise ValueError(f"no Responses-API equivalent for generation_kwargs {sorted(kwargs)}")
    params["chat_generator"] = {
        "type": GYM_GENERATOR,
        "init_parameters": {"server_name": server_name, "generation_kwargs": responses_kwargs},
    }
    if params.get("user_prompt") is not None:
        raise ValueError("Gym's harness supplies the user message itself; the agent must not set user_prompt")
    return {
        "components": {"agent": agent},
        "connections": [],
        "connection_type_validation": True,
        "max_runs_per_component": 100,
        "metadata": {},
    }
