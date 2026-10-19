# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import copy
import json

from fake_vllm import FakeVllm
from haystack.dataclasses import ChatMessage, ToolCall
from helpers import SEED, PairBenchmark, model

from security_agent.generator import make_generator, unwrap_reasoning
from security_agent.synthetic.agent import make_scanner
from security_agent.synthetic.gym import REPEAT_KEY, Scorer, response_items, scan, scanner_model, task_rows


def test_rows_name_both_repositories_of_each_pair_and_no_answers(tmp_path):
    bench = PairBenchmark(tmp_path)
    rows = task_rows(bench, ["pair-a", "pair-b"])
    expected = [(p["pair_id"], p[key]) for p in bench.pairs for key in ("mutant_instance_id", "baseline_instance_id")]
    assert [(r["pair_id"], r["instance_id"]) for r in rows] == expected
    assert all(r["responses_create_params"]["metadata"] == {"instance_id": r["instance_id"]} for r in rows)
    assert set(rows[0]) == {"responses_create_params", "instance_id", "pair_id"}  # the answer key stays server-side


def test_a_gym_model_server_gets_vllm_options_as_metadata():
    settings = scanner_model({"model": "m", "api_base_url": "http://vllm/v1"}, "http://gym/ng-rollout/r1/v1")
    assert settings["api_base_url"] == "http://gym/ng-rollout/r1/v1" and settings["gym_model_server"]
    budget = make_generator(settings, max_tokens=10, thinking_budget=512).generation_kwargs
    assert "extra_body" not in budget and json.loads(budget["metadata"]["extra_body"]) == {"thinking_token_budget": 512}
    off = make_generator(settings, max_tokens=10, thinking_budget=None).generation_kwargs
    assert json.loads(off["metadata"]["chat_template_kwargs"]) == {"enable_thinking": False}
    vllm = make_generator({"model": "m", "api_base_url": "x"}, max_tokens=10, thinking_budget=512).generation_kwargs
    assert vllm["extra_body"] == {"thinking_token_budget": 512} and "metadata" not in vllm


def test_reasoning_that_gym_wrapped_in_think_tags_goes_back_to_its_field():
    answer = unwrap_reasoning(ChatMessage.from_assistant("<think>Check the escape.</think>Done.", meta={"n": 1}))
    assert answer.text == "Done." and answer.reasoning.reasoning_text == "Check the escape." and answer.meta == {"n": 1}
    call = ToolCall(tool_name="read_file", arguments={"path": "a.py"})
    step = unwrap_reasoning(ChatMessage.from_assistant("<think>Read it.</think>", tool_calls=[call]))
    assert step.text is None and step.tool_calls == [call] and step.reasoning.reasoning_text == "Read it."
    plain = ChatMessage.from_assistant("No tags.")
    assert unwrap_reasoning(plain) is plain


def test_scans_are_scored_per_repository_and_per_pair(tmp_path):
    bench = PairBenchmark(tmp_path)
    scorer = Scorer(bench)
    rows = task_rows(bench, ["pair-a", "pair-b"])
    paths = {i.instance_id: i.path for i in bench.instances()}
    verified = []
    with FakeVllm() as server:
        scanner = make_scanner(SEED, scanner_model(model(server.base_url), server.base_url))
        for row in rows:
            report, record, findings = scan(scanner, row["instance_id"], paths[row["instance_id"]])
            assert report.status == "complete"
            verified.append({**row, **scorer.reward(row["instance_id"], findings), "findings": findings})
        sent = list(server.requests)
    assert sent and all(body.get("metadata") and "thinking_token_budget" not in body for body in sent)
    # The fake agent reports the SELECT line, 9: pair-a's planted line; pair-b's is 5. The fixed twins have none.
    assert [v["reward"] for v in verified] == [1.0, 1.0, 0.0, 1.0]
    assert [v["member"] for v in verified] == ["mutant", "baseline", "mutant", "baseline"]
    metrics = scorer.pair_metrics(verified)
    assert metrics["pairs"] == 2 and metrics["paired_localization_accuracy"] == 0.5
    assert metrics["baseline_mapped_localization_false_alarm_rate"] == 0.0
    assert scorer.pair_metrics(verified[:3])["pairs"] == 1  # pair-b's fixed twin was not scanned: pair-a only

    fixed = copy.deepcopy(verified)
    fixed[2]["findings"][0].update(line_start=5, line_end=5)  # a second repeat that gets pair-b right too
    repeats = [{**v, REPEAT_KEY: 0} for v in verified] + [{**v, REPEAT_KEY: 1} for v in fixed]
    assert scorer.mean_over_repeats(repeats)["paired_localization_accuracy"] == 0.75

    items = response_items(record["agent"]["trajectory"])
    calls = [i["call_id"] for i in items if i["type"] == "function_call"]
    outputs = [i["call_id"] for i in items if i["type"] == "function_call_output"]
    assert calls and calls == outputs
    assert items[-1]["type"] == "message" and items[-1]["content"][0]["text"] == "Done: reviewed the repository."
