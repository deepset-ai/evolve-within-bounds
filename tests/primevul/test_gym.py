# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""The NeMo Gym environment's scoring, export and pipeline conversion, without Gym installed."""

import json
from pathlib import Path

import pytest
from pv_helpers import write_benchmark

from security_agent.primevul.agent import load_config
from security_agent.primevul.gym import (
    GYM_GENERATOR,
    REPEAT_KEY,
    export,
    final_text,
    harness_pipeline,
    mean_over_repeats,
    pair_metrics,
    score,
)
from security_agent.primevul.tasks import load_tasks

REPO = Path(__file__).resolve().parents[2]
VULNERABLE = json.dumps({"is_vulnerable": True, "cwe": "cwe-787", "vulnerable_lines": [3], "rationale": "unbounded"})
BENIGN = json.dumps({"is_vulnerable": False, "cwe": None, "vulnerable_lines": [], "rationale": "bounded"})


def response(text: str) -> dict:
    """A Responses-API response: reasoning, a tool call and its output, then the answer."""
    return {
        "output": [
            {"type": "reasoning", "summary": [{"type": "summary_text", "text": "thinking"}]},
            {"type": "function_call", "name": "search_security_kb", "arguments": "{}", "call_id": "1"},
            {"type": "function_call_output", "call_id": "1", "output": '{"is_vulnerable": false}'},
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]},
        ]
    }


def test_rows_carry_our_user_message_and_the_labels(tmp_path):
    data = write_benchmark(tmp_path / "b.jsonl")
    out = tmp_path / "rows.jsonl"
    assert export(data, "holdout", out, max_pairs=1) == 2
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    task = load_tasks(data, "holdout", 1)[0]
    assert rows[0]["responses_create_params"] == {"input": [{"role": "user", "content": task.question}]}
    assert rows[0] | {"responses_create_params": None} == {
        "responses_create_params": None,
        "task_id": "holdout-0-v",
        "pair_id": "holdout-0",
        "gold_is_vulnerable": True,
        "gold_cwe": "CWE-787",
    }


def test_the_example_rows_have_the_export_shape():
    rows = [
        json.loads(line)
        for line in (REPO / "gym/resources_servers/primevul/data/example.jsonl").read_text().splitlines()
    ]
    assert len(rows) == 4
    assert all(
        set(r) == {"responses_create_params", "task_id", "pair_id", "gold_is_vulnerable", "gold_cwe"} for r in rows
    )


def test_score_reads_the_final_message_only():
    row = {"gold_is_vulnerable": True, "gold_cwe": "CWE-787"}
    assert final_text(response(VULNERABLE)) == VULNERABLE
    scored = score(response(VULNERABLE), row)
    assert scored == {
        "reward": 1.0,
        "correct": True,
        "parse_error": False,
        "pred_is_vulnerable": True,
        "pred_cwe": "CWE-787",
        "cwe_correct": True,
    }
    assert score(response(BENIGN), row)["reward"] == 0.0
    missing = score({"output": []}, row)
    assert missing["parse_error"] and missing["reward"] == 0.0 and missing["pred_is_vulnerable"] is None


def test_pair_metrics_match_the_runner():
    def row(pid, vulnerable, predicted):
        return {
            "task_id": f"{pid}-{'v' if vulnerable else 'f'}",
            "pair_id": pid,
            "gold_is_vulnerable": vulnerable,
            "gold_cwe": "CWE-787" if vulnerable else None,
            "pred_is_vulnerable": predicted,
            "parse_error": predicted is None,
        }

    rows = [row("a", True, True), row("a", False, False), row("b", True, True), row("b", False, True)]
    rows += [row("c", True, None), row("c", False, False), row("d", True, True)]  # d has no twin: not a pair
    metrics = pair_metrics(rows)
    assert metrics["pairs"] == 3
    assert metrics["paired_accuracy"] == pytest.approx(1 / 3)
    assert metrics["pairs_missed_fix"] == 1 and metrics["pairs_parse_error"] == 1
    assert metrics["pair_false_positive_rate"] == pytest.approx(1 / 2)
    assert pair_metrics([]) == {}


def test_repeats_are_scored_apart_then_averaged():
    def row(pid, vulnerable, predicted, repeat):
        return {
            "task_id": f"{pid}-{vulnerable}",
            "pair_id": pid,
            "gold_is_vulnerable": vulnerable,
            "pred_is_vulnerable": predicted,
            "parse_error": False,
            REPEAT_KEY: repeat,
        }

    rows = [row("a", True, True, 0), row("a", False, False, 0), row("a", True, True, 1), row("a", False, True, 1)]
    assert mean_over_repeats(rows)["paired_accuracy"] == pytest.approx(0.5)  # pooled, it would be 0


@pytest.mark.parametrize("name", ["seed", "looped"])
def test_harness_pipeline_swaps_only_the_generator(name):
    agent = load_config(REPO / "agents" / "primevul" / name)
    pipeline = harness_pipeline(agent)
    converted = pipeline["components"]["agent"]
    assert converted["init_parameters"]["chat_generator"] == {
        "type": GYM_GENERATOR,
        "init_parameters": {
            "server_name": "policy_model",
            "generation_kwargs": {"max_output_tokens": 8000, "temperature": 0.0},
        },
    }
    for key in ("system_prompt", "tools", "max_agent_steps", "exit_conditions", "tool_concurrency_limit"):
        assert converted["init_parameters"][key] == agent["init_parameters"][key]
    assert pipeline["connections"] == []


def test_harness_pipeline_refuses_what_gym_cannot_send():
    agent = load_config(REPO / "agents" / "primevul" / "seed")
    agent["init_parameters"]["chat_generator"]["init_parameters"]["generation_kwargs"]["top_k"] = 5
    with pytest.raises(ValueError, match="top_k"):
        harness_pipeline(agent)
