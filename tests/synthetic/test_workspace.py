# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json
import shutil

import pytest
from fake_vllm import FakeVllm
from haystack.tools.errors import ToolInvocationError
from helpers import SEED, OnePairBench, model
from test_agent import SEARCH

from security_agent.optimize import candidate as cand
from security_agent.optimize.leakage import Leakage
from security_agent.optimize.proposer import _exit_tools, agent_proposer, step_reminder
from security_agent.optimize.workspace import Workspace
from security_agent.synthetic.agent import check_candidate, contract_test
from security_agent.synthetic.config import load_yaml
from security_agent.synthetic.examples import Examples
from security_agent.synthetic.task import TOOL_SPECS, SyntheticTask
from security_agent.synthetic.traces import MAX_READS

STEPS = "max_agent_steps: 15"


def _workspace(tmp_path, leakage=None, **options):
    reference = tmp_path / "reference"
    shutil.copytree(SEED, reference)
    options = {"check": check_candidate, "contract_check": contract_test, "tool_specs": TOOL_SPECS, **options}
    ws = Workspace(
        tmp_path / "draft", {cand.candidate_id(reference): reference}, (leakage or Leakage()).check, **options
    )
    ws.begin_turn(cand.candidate_id(reference))
    return ws


def test_workspace_edit_validate_submit(tmp_path):
    ws = _workspace(tmp_path)
    rev = json.loads(ws.read_file("pipeline.yaml"))["revision"]
    assert (
        "Stale or missing expected_revision"
        in json.loads(ws.edit_file("pipeline.yaml", STEPS, "max_agent_steps: 20", "nope"))["error"]
    )
    assert "occurs" in json.loads(ws.edit_file("pipeline.yaml", "_chars: 8000", "_chars: 9000", rev))["error"]
    assert (
        "not found"
        in json.loads(ws.edit_file("pipeline.yaml", "max_agent_steps: 99", "max_agent_steps: 20", rev))["error"]
    )
    assert "no such file" in json.loads(ws.edit_file("../etc/passwd", "a", "b", rev))["error"]
    assert "invalid YAML" in json.loads(ws.edit_file("pipeline.yaml", STEPS, "max_agent_steps: [", rev))["error"]
    edited = json.loads(ws.edit_file("pipeline.yaml", STEPS, "max_agent_steps: 20", rev))
    assert edited["ok"] and edited["revision"] != rev
    assert "Not validated" in json.loads(ws.submit_candidate("more steps", edited["revision"]))["error"]
    assert json.loads(ws.validate_candidate())["valid"]
    result = json.loads(ws.submit_candidate("more steps reach more files", edited["revision"]))
    assert result["ok"] and ws.submitted.candidate_id == edited["revision"]
    assert "+      max_agent_steps: 20" in ws.submitted.diff


def test_workspace_refuses_no_ops_and_leaks(tmp_path):
    leakage = Leakage()
    leakage.add({"paths": ["src/custom_components/token_reader.py"]})
    ws = _workspace(tmp_path, leakage)
    assert "no_op" in json.loads(ws.validate_candidate())["errors"][0]
    rev = json.loads(ws.edit_file("pipeline.yaml", STEPS, "max_agent_steps: 15  # same", ws.revision))["revision"]
    assert "no_op" in json.loads(ws.validate_candidate())["errors"][0]  # a comment is not a change
    first = (ws.draft / "prompts/system.md").read_text().splitlines()[0]
    ws.edit_file("prompts/system.md", first, first + "\nCheck token_reader.py first.", rev)
    errors = json.loads(ws.validate_candidate())["errors"]
    assert errors and "leakage" in errors[0] and "token_reader.py" in errors[0]


def test_workspace_writes_and_deletes_only_code_files(tmp_path):
    ws = _workspace(tmp_path)
    assert "only creates or replaces tools/" in json.loads(ws.write_file("prompts/x.md", "x", ws.revision))["error"]
    assert json.loads(ws.write_file("tools/search.py", SEARCH, ws.revision))["ok"]
    assert any("does not use" in e for e in json.loads(ws.validate_candidate())["errors"])
    assert json.loads(ws.delete_file("tools/search.py", ws.revision))["ok"] and ws.revision == ws.parent_id


def test_exit_tools_raise_on_refusal_so_the_agent_continues(tmp_path):
    ws = _workspace(tmp_path)
    submit = next(t for t in _exit_tools(ws) if t.name == "submit_candidate")
    with pytest.raises(ToolInvocationError, match="Not validated"):
        submit.invoke(rationale="x", expected_revision=ws.revision)


def test_agent_proposer_recovers_from_a_refused_submit(tmp_path):
    ws = _workspace(tmp_path)
    settings = {"thinking_budget": 256, "max_tokens": 2048, "temperature": 0.0, "max_steps": 8, "nudges": 1}
    task = SyntheticTask(model_config={"api_base_url": "http://127.0.0.1:1/v1", "model": "fake"})
    system = task.system_prompt(task.prompt_values(load_yaml("loop.yaml"), {"hvbench": ["p1", "p2"]}))
    with FakeVllm() as server:
        propose = agent_proposer(model(server.base_url), settings, system)
        sub, info = propose(ws, ["static", "outcomes", f"Revision: `{ws.revision}`"], tmp_path / "turn-000.json")
        system = server.requests[0]["messages"][0]["content"]
    assert info["tool_calls"] == ["submit_candidate", "edit_file", "validate_candidate", "submit_candidate"]
    assert sub is not None and not sub.auto and "+      max_agent_steps: 20" in sub.diff
    assert "## The contract" in system and "$limits" not in system and "2 pairs (4 repositories)" in system
    saved = json.loads((tmp_path / "turn-000.json").read_text())
    assert saved["info"]["submitted"] == sub.candidate_id and len(saved["messages"]) >= 8


def test_auto_submit_measures_an_edited_valid_draft(tmp_path):
    ws = _workspace(tmp_path)
    assert ws.auto_submit("nothing") is None
    ws.edit_file("pipeline.yaml", STEPS, "max_agent_steps: 18", ws.revision)
    sub = ws.auto_submit("I raised the steps")
    assert sub is not None and sub.auto and "auto-submitted" in sub.rationale


def test_reasoning_reads_are_capped_and_required_before_submit(tmp_path):
    calls = []
    ws = _workspace(
        tmp_path, reasoning_reader=lambda example, side, run: calls.append(example) or "{}", min_reasoning_reads=2
    )
    ws.edit_file("pipeline.yaml", STEPS, "max_agent_steps: 18", ws.revision)
    assert json.loads(ws.validate_candidate())["valid"]
    refused = json.loads(ws.submit_candidate("try", ws.revision))
    assert not refused["ok"] and "at least 2" in refused["error"] and ws.submitted is None
    for _ in range(MAX_READS):
        ws.read_reasoning("hvbench/pair-x")
    assert "at most" in json.loads(ws.read_reasoning("hvbench/pair-x"))["error"] and len(calls) == MAX_READS
    assert json.loads(ws.submit_candidate("try", ws.revision))["ok"]
    assert not any(t.name == "read_reasoning" for t in _workspace(tmp_path / "2").tools())


def test_run_tool_and_trial_scan_on_a_training_pair(tmp_path):
    bench = OnePairBench(tmp_path)
    with FakeVllm() as server:
        examples = Examples(
            {"hvbench": ["pair-x"]}, lambda b, iid: None, bench_loader=lambda name: bench, model=model(server.base_url)
        )
        ws = _workspace(tmp_path, contract_check=lambda d: [], example_runner=examples, trial_runner=examples.trial)
        assert "trial_scan" in [t.name for t in ws.tools()]
        ws.write_file("tools/search.py", SEARCH, ws.revision)
        assert (
            "not a training pair key"
            in json.loads(ws.run_tool("tools/search.py", "hvbench/pair-y", {"pattern": "x"}))["error"]
        )
        out = json.loads(ws.run_tool("tools/search.py", "hvbench/pair-x", {"pattern": "requests"}))
        assert out["ok"] and "src/fetch.py:5:" in out["vulnerable"]["output"] and "safe_twin" not in out
        ws.edit_file(
            "pipeline.yaml", "      - run_python\n", "      - run_python\n      - tools/search.py\n", ws.revision
        )
        assert json.loads(ws.validate_candidate())["valid"]
        trial = json.loads(ws.trial_scan("hvbench/pair-x"))
        assert trial["ok"] and set(trial) >= {"vulnerable", "safe_twin", "pair_right"}
        assert (
            trial["vulnerable"]["agent"]["tool_calls"]["search"] == 1
            and trial["vulnerable"]["agent"]["read_planted_file"]
        )
        for _ in range(2):
            ws.trial_scan("hvbench/pair-x")
        assert "at most 3 trial scans" in json.loads(ws.trial_scan("hvbench/pair-x"))["error"]


def test_step_reminder_tells_the_optimizer_to_submit():
    from haystack.components.agents import Agent
    from haystack.dataclasses import ChatMessage
    from haystack.tools import Tool

    from security_agent.generator import make_generator

    with FakeVllm() as server:
        generator = make_generator(model(server.base_url), max_tokens=256, thinking_budget=None)
        parameters = {"type": "object", "properties": {"pattern": {"type": "string"}}}
        tools = [
            Tool(name="report_finding", description="d", parameters=parameters, function=lambda **_: "reported"),
            Tool(name="search", description="d", parameters=parameters, function=lambda **_: "no match"),
        ]
        agent = Agent(
            chat_generator=generator, tools=tools, max_agent_steps=2, hooks={"before_llm": [step_reminder(2)]}
        )
        agent.run(messages=[ChatMessage.from_user("Files (1):\nsrc/a.py (1 lines)")])
        texts = [json.dumps(r["messages"]) for r in server.requests]
    assert "steps in this turn are left" not in texts[0] and "[1 of your 2 steps in this turn are left." in texts[-1]


def test_the_observer_sees_every_tool_call_and_refusal(tmp_path):
    from security_agent.optimize.proposer import _observed

    ws = _workspace(tmp_path)
    calls = []
    tools = {t.name: t for t in _observed(_exit_tools(ws), lambda name, args, result: calls.append((name, args)))}
    tools["list_files"].function()
    with pytest.raises(Exception, match="Not validated"):
        tools["submit_candidate"].function(rationale="x", expected_revision=ws.revision)
    assert [name for name, _ in calls] == ["list_files", "submit_candidate"]
    assert calls[1][1]["rationale"] == "x"
