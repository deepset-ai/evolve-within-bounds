# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json

import pytest
from fake_vllm import FakeVllm
from helpers import LOOPED, SEED, STORE, UTIL, FakeBenchmark, candidate, model

import security_agent.synthetic.agent as agent_module
from security_agent.optimize import candidate as cand
from security_agent.synthetic.agent import (
    AgentScanner,
    ScanAgent,
    ScanContext,
    check_candidate,
    contract_test,
    pipeline_problems,
)
from security_agent.synthetic.bench.runner import run
from security_agent.synthetic.measure import record_cost

SEARCH = """KIND = "tool"
DESCRIPTION = "Search the repository for a regular expression; returns path:line: text."
PARAMETERS = {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}
EXAMPLE = {"pattern": "urlopen"}


def run(ctx, pattern):
    ctx.state["searches"] = ctx.state.get("searches", 0) + 1
    hits = ctx.repo.grep(pattern, glob="*.py")
    return "\\n".join(f"{p}:{n}: {t.strip()}" for p, n, t in hits) or "no match"
"""

# After the agent: ask the model about each finding; keep only SQL injection.
CHECK = """KIND = "step"


def run(ctx):
    answers = ctx.llm.ask_many([{"prompt": "Real? " + f["title"], "schema": {"type": "object"}} for f in ctx.findings])
    for finding, answer in zip(list(ctx.findings), answers):
        if finding["cwe"] != "CWE-89":
            ctx.retract(finding["id"])
    ctx.note("unused after the agent")
"""

# Before the agent: report a candidate of its own and leave the agent a note.
HUNT = """KIND = "step"


def run(ctx):
    for path, line, text in ctx.repo.grep("def ", glob="*.py")[:1]:
        ctx.report(path, line, line, "CWE-20", "first function", confidence=40)
    ctx.note("Look at the SQL in store.py first.")
"""

CODE = {"search.py": SEARCH, "check.py": CHECK, "hunt.py": HUNT}


def _with_code(data):
    """The search tool for the agent, a step before it and a checking step after it."""
    agent = data["components"]["agent"]["init_parameters"]
    agent["tools"] = ["read_file", "tools/search.py"]
    agent.update(tool_model_calls=5, tool_completion_tokens=5000)
    data["components"]["hunt"] = {
        "type": "security_agent.synthetic.agent.CodeStep",
        "init_parameters": {"code": "tools/hunt.py", "max_calls": 0},
    }
    data["components"]["check"] = {
        "type": "security_agent.synthetic.agent.CodeStep",
        "init_parameters": {"code": "tools/check.py", "max_calls": 10},
    }
    data["connections"] = [
        {"sender": "hunt.findings", "receiver": "agent.findings"},
        {"sender": "agent.findings", "receiver": "check.findings"},
        {"sender": "check.findings", "receiver": "normalizer.candidates"},
    ]


def _bench(tmp_path):
    return FakeBenchmark(tmp_path, n=1, files={"src/pkg/store.py": STORE, "src/pkg/util.py": UTIL})


@pytest.mark.parametrize("directory", [SEED, LOOPED])
def test_the_shipped_candidates_are_valid(directory):
    assert check_candidate(directory) == [] and contract_test(directory) == []


def test_seed_reports_through_report_finding(tmp_path):
    bench = _bench(tmp_path)
    with FakeVllm() as server:
        summary = run(
            bench, AgentScanner(SEED, model_config=model(server.base_url)), tmp_path / "run", log=lambda *_: None
        )
    assert summary.complete == summary.selected == 1
    record = json.loads(next((tmp_path / "run/records").glob("*.json")).read_text())
    agent = record["agent"]
    assert agent["stop"] == "answered" and agent["steps"] == 3 and agent["reads"][0]["path"] == "src/pkg/store.py"
    assert [c["tool"] for c in agent["tool_calls"]] == ["read_file", "report_finding"]
    assert [m["role"] for m in agent["trajectory"]] == ["user", "assistant", "tool", "assistant", "tool", "assistant"]
    prediction = json.loads((tmp_path / "run/predictions.jsonl").read_text())
    assert [(f["path"], f["line_start"], f["cwe"]) for f in prediction["findings"]] == [
        ("src/pkg/store.py", 9, "CWE-89")
    ]
    assert record_cost(record)["calls"] == 3


def test_optimizer_code_runs_as_tool_and_steps(tmp_path):
    directory = candidate(tmp_path, _with_code, CODE)
    assert check_candidate(directory) == [] and contract_test(directory) == []
    with FakeVllm() as server:
        run(
            _bench(tmp_path),
            AgentScanner(directory, model_config=model(server.base_url)),
            tmp_path / "run",
            log=lambda *_: None,
        )
        asked = [r for r in server.requests if "Real?" in json.dumps(r.get("messages"))]
    record = json.loads(next((tmp_path / "run/records").glob("*.json")).read_text())
    agent = record["agent"]
    assert [c["tool"] for c in agent["tool_calls"]][:2] == ["search", "read_file"] and agent["tool_calls"][0]["ok"]
    assert (
        "Look at the SQL in store.py first." in agent["trajectory"][0]["text"]
    )  # the step before the agent left a note
    hunt, check = record["components"]
    assert hunt["ok"] and hunt["kept"] == 1 and agent["received"][0]["cwe"] == "CWE-20"
    assert check["ok"] and check["input"] == 2 and check["kept"] == 1 and len(check["calls"]) == 2 == len(asked)
    prediction = json.loads((tmp_path / "run/predictions.jsonl").read_text())
    assert [f["cwe"] for f in prediction["findings"]] == ["CWE-89"]
    assert record_cost(record)["calls"] == agent["steps"] + 2  # the step's two model calls count


def test_budget_stops_the_agent_and_keeps_its_findings(tmp_path):
    (tmp_path / "repo" / "src").mkdir(parents=True)
    (tmp_path / "repo" / "src" / "store.py").write_text(STORE)
    with FakeVllm() as server:  # every fake call costs 20 output tokens: the budget of 30 refuses the third call
        agent = ScanAgent(
            str(SEED / "prompts/system.md"),
            str(SEED / "prompts/user.jinja2"),
            ["read_file"],
            model=model(server.base_url),
            scan="k",
            scan_completion_tokens=30,
        )
        agent_module._CONTEXTS["k"] = ScanContext(str(tmp_path / "repo"), ["src/store.py"])
        try:
            out = agent.run()
        finally:
            agent_module._CONTEXTS.pop("k")
    record = out["record"]
    assert (
        record["stop"] == "budget: output tokens: 30 per repository" and record["steps"] == 2 and not record["outage"]
    )
    assert [f["cwe"] for f in out["findings"]] == ["CWE-89"]  # reported before the budget ran out: kept


@pytest.mark.parametrize(
    "edit, code, problem",
    [
        (lambda d: d["components"].pop("agent"), None, "exactly one ScanAgent"),
        (lambda d: d["components"]["agent"]["init_parameters"].__setitem__("model", {}), None, "set by the experiment"),
        (
            lambda d: d["components"]["agent"]["init_parameters"].__setitem__("max_agent_steps", 5000),
            None,
            "outside the allowed range",
        ),
        (
            lambda d: d["components"]["agent"]["init_parameters"].update(thinking_budget=8000, max_tokens=8192),
            None,
            "thinking_budget + 1024",
        ),
        (lambda d: d["components"]["agent"]["init_parameters"]["tools"].append("shell"), None, "neither built in"),
        (lambda d: d["components"]["normalizer"]["init_parameters"].__setitem__("tau", 50), None, "tau is fixed at 0"),
        (
            lambda d: d["components"]["agent"]["init_parameters"]["tools"].append("tools/leaky.py"),
            {
                "leaky.py": SEARCH.replace(
                    "hits = ctx.repo.grep", "secret = open('/etc/hosts').read()\n    hits = ctx.repo.grep"
                )
            },
            "'open' is not allowed",
        ),
        (
            lambda d: d["components"]["agent"]["init_parameters"]["tools"].append("tools/paths.py"),
            {"paths.py": "import pathlib\n" + SEARCH},
            "import of 'pathlib' is not allowed",
        ),
        (
            lambda d: d["components"]["agent"]["init_parameters"]["tools"].append("tools/check.py"),
            {"check.py": CHECK},
            "the agent's tools have KIND",
        ),
    ],
)
def test_contract(tmp_path, edit, code, problem):
    directory = candidate(tmp_path, edit, code)
    assert any(problem in p for p in pipeline_problems(directory)), pipeline_problems(directory)


def test_contract_test_runs_the_code_on_the_fixture(tmp_path):
    fragile = SEARCH.replace('EXAMPLE = {"pattern": "urlopen"}', 'EXAMPLE = {"pattern": "x"}').replace(
        "    hits = ctx.repo.grep", "    score = ctx.llm.ask('rate')['json']['score']\n    hits = ctx.repo.grep"
    )
    directory = candidate(
        tmp_path,
        lambda d: d["components"]["agent"]["init_parameters"]["tools"].append("tools/fragile.py"),
        {"fragile.py": fragile},
    )
    assert any("must cope" in e and "TypeError" in e for e in contract_test(directory))
    bad_step = 'KIND = "step"\n\n\ndef run(ctx):\n    ctx.findings.append({"path": "nowhere.py"})\n'

    def wire(d):
        d["components"]["bad"] = {
            "type": "security_agent.synthetic.agent.CodeStep",
            "init_parameters": {"code": "tools/bad.py"},
        }
        d["connections"] = [
            {"sender": "agent.findings", "receiver": "bad.findings"},
            {"sender": "bad.findings", "receiver": "normalizer.candidates"},
        ]

    assert any(
        "must stay a list of valid findings" in e
        for e in contract_test(candidate(tmp_path, wire, {"bad.py": bad_step}, "b"))
    )
    unused = candidate(tmp_path, None, {"search.py": SEARCH}, "u")
    assert any("does not use" in e for e in check_candidate(unused))


def test_candidate_id_ignores_comments(tmp_path):
    copy = candidate(tmp_path)
    text = (copy / "pipeline.yaml").read_text()
    (copy / "pipeline.yaml").write_text(text.replace("max_agent_steps: 15", "max_agent_steps: 15   # a comment"))
    assert cand.candidate_id(copy) == cand.candidate_id(SEED)
    (copy / "pipeline.yaml").write_text(text.replace("max_agent_steps: 15", "max_agent_steps: 16"))
    assert cand.candidate_id(copy) != cand.candidate_id(SEED)
