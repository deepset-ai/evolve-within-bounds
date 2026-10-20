# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""Judging functions inside the OpenShell sandbox, against a fake `openshell` CLI and a fake agent."""

import json
from pathlib import Path

import pytest
from haystack.dataclasses import ChatMessage
from openshell_fake import FakeOpenShell
from pv_helpers import write_benchmark
from test_measure import BENIGN, FakeAgent

import security_agent.primevul.sandbox as sandbox_module
import security_agent.sandbox as base_module
from security_agent import cli
from security_agent.knowledge_base.search import SecurityKbSearch
from security_agent.knowledge_base.store import KbStoreError
from security_agent.primevul import agent as agents
from security_agent.primevul.measure import measure
from security_agent.primevul.sandbox import OpenShell, SandboxError
from security_agent.primevul.tasks import load_tasks

SEED = Path(__file__).resolve().parents[2] / "agents" / "primevul" / "seed"


@pytest.fixture
def jobs(monkeypatch):
    """The jobs the sandbox ran, as it received them."""
    seen = []
    execute = sandbox_module._execute

    def recording(job, root):
        seen.append(job)
        return execute(job, root)

    monkeypatch.setattr(sandbox_module, "_execute", recording)
    return seen


@pytest.fixture
def fake_agent(monkeypatch):
    monkeypatch.setattr(agents, "load_agent", lambda config: FakeAgent(final=[ChatMessage.from_assistant(BENIGN)]))


def _run_args(data, run_dir):
    return ["primevul", "run", "--agent", str(SEED), "--data", str(data), "--run-dir", str(run_dir)]


def _sandbox(tmp_path, **fake):
    shell = FakeOpenShell(tmp_path / "sandbox-fs", **fake)
    return OpenShell("sbx", runner=shell, spawner=shell.spawn), shell


def test_functions_judged_in_the_sandbox_match_the_host(tmp_path, jobs, fake_agent):
    tasks = load_tasks(write_benchmark(tmp_path / "b.jsonl"), "train")
    config = agents.load_config(SEED)
    host, host_records = measure(config, tasks, concurrency=1, log=lambda _: None, load_agent=agents.load_agent)
    sandbox, shell = _sandbox(tmp_path)
    inside, records = measure(config, tasks, concurrency=1, log=lambda _: None, sandbox=sandbox)

    assert inside.counts == host.counts and inside.counts["correct"] == 1 and inside.counts["parse_error"] == 1
    for task_id, record in records.items():
        assert {k: v for k, v in record.items() if k != "seconds"} == {
            k: v for k, v in host_records[task_id].items() if k != "seconds"
        }
    assert records["train-1-f"]["error"] == "RuntimeError: server went away"  # the agent's failure, kept as on the host
    assert shell.leftovers() == []  # jobs and results are removed

    # Only the agent file and the function's user message enter the sandbox.
    assert len(jobs) == 4 and {tuple(sorted(job)) for job in jobs} == {("agent", "code_version", "kind", "question")}
    assert not any(task.id in json.dumps(jobs) for task in tasks)
    generator = jobs[0]["agent"]["init_parameters"]["chat_generator"]["init_parameters"]
    kb = jobs[0]["agent"]["init_parameters"]["tools"][0]["data"]["component"]["init_parameters"]
    assert generator["api_base_url"] == kb["llm_base_url"] == "https://inference.local/v1"
    assert kb["qdrant_url"] == "http://host.openshell.internal:6333"
    assert config["init_parameters"]["chat_generator"]["init_parameters"]["api_base_url"] == "http://127.0.0.1:8000/v1"


def test_a_function_the_sandbox_failed_to_judge_is_judged_on_resume(tmp_path, fake_agent):
    tasks = load_tasks(write_benchmark(tmp_path / "b.jsonl"), "train")
    cache = tmp_path / "run" / "tasks.json"
    sandbox, shell = _sandbox(tmp_path, fail_execs=2)  # the first job, and its retry
    config = agents.load_config(SEED)
    lines = []
    metrics, records = measure(config, tasks, concurrency=1, log=lines.append, cache=cache, sandbox=sandbox)
    assert "train-0-v" not in records and len(records) == 3
    assert metrics.counts["parse_error"] == 2  # train-0 is missing a verdict, train-1's patched twin raised
    assert any("relay closed" in line for line in lines)

    again, records = measure(config, tasks, concurrency=1, log=lambda _: None, cache=cache, sandbox=sandbox)
    assert len(records) == 4 and again.counts["correct"] == 1 and again.counts["parse_error"] == 1
    assert len([c for c in shell.calls if "run-job" in c]) == 2 + 3 + 1


def test_the_loop_measures_again_what_the_sandbox_failed_to_judge(tmp_path, fake_agent):
    from security_agent.primevul.task import PrimeVulTask

    data = write_benchmark(tmp_path / "b.jsonl")
    sandbox, _ = _sandbox(tmp_path, fail_execs=2)
    task = PrimeVulTask(SEED, data=data, concurrency=1, sandbox=sandbox, log=lambda *_: None)
    m = task.measure(SEED, [{"primevul": ["train-0", "train-1"]}], tmp_path / "m", label="reference")
    assert m.instances == 4 and m.incomplete == 1
    assert task.spoiled(m) == 1
    again = task.measure(SEED, [{"primevul": ["train-0", "train-1"]}], tmp_path / "m", label="reference")
    assert again.incomplete == 0 and task.spoiled(again) == 0


def test_the_check_names_what_the_agent_cannot_reach(tmp_path, monkeypatch):
    from security_agent import generator

    sandbox, _ = _sandbox(tmp_path)
    config = agents.load_config(SEED)
    asked = []

    def answers(url, model, timeout_s=60.0):
        asked.append((url, model))
        return True

    monkeypatch.setattr(generator, "server_answers", answers)
    monkeypatch.setattr(SecurityKbSearch, "retrieve", lambda self, query, top_k=None: [self.qdrant_url])
    assert sandbox.check(config) == {"model": True, "documents": 1}
    assert asked == [("https://inference.local/v1", "qwen3.8-flash-next")]

    def unreachable(self, query, top_k=None):
        raise KbStoreError(f"Cannot reach Qdrant at {self.qdrant_url}")

    monkeypatch.setattr(generator, "server_answers", lambda url, model, timeout_s=60.0: False)
    monkeypatch.setattr(SecurityKbSearch, "retrieve", unreachable)
    with pytest.raises(SandboxError) as error:
        sandbox.check(config)
    assert "the model does not answer" in str(error.value)
    assert "Cannot reach Qdrant at http://host.openshell.internal:6333" in str(error.value)

    def refused(self, query, top_k=None):
        raise KbStoreError("403 (Forbidden): GET host.openshell.internal:6333 blocked: allowed_ips check failed")

    monkeypatch.setattr(SecurityKbSearch, "retrieve", refused)
    with pytest.raises(SandboxError, match="the sandbox's policy refused the request"):
        sandbox.check(config)

    monkeypatch.setattr(SecurityKbSearch, "retrieve", lambda self, query, top_k=None: [])
    with pytest.raises(SandboxError, match="primevul:kb build"):
        sandbox.check(config)


def test_run_judges_in_the_sandbox_after_the_check(tmp_path, monkeypatch, fake_agent, capsys):
    shell = FakeOpenShell(tmp_path / "sandbox-fs")
    monkeypatch.setattr(base_module, "_run", shell)
    monkeypatch.setattr(base_module, "_spawn", shell.spawn)
    monkeypatch.setattr(sandbox_module, "_check", lambda job: {"model": True, "documents": 1})
    data = write_benchmark(tmp_path / "b.jsonl")
    run_dir = tmp_path / "run"
    args = ["primevul", "run", "--agent", str(SEED), "--data", str(data), "--split", "train", "--pairs", "1"]
    with pytest.raises(SystemExit) as code:
        cli.main([*args, "--concurrency", "1", "--run-dir", str(run_dir), "--sandbox", "sbx"])
    assert code.value.code == 0
    summary = json.loads((run_dir / "summary.json").read_text())
    assert summary["sandbox"] == "sbx" and summary["metrics"]["counts"]["correct"] == 1
    out = capsys.readouterr().out
    assert out.startswith("sandbox sbx: the agent reaches the model and the knowledge base")
    assert len([c for c in shell.calls if "run-job" in c]) == 1 + 2 and shell.leftovers() == []


def test_a_sandbox_that_cannot_reach_the_knowledge_base_stops_the_run(tmp_path, monkeypatch, capsys):
    shell = FakeOpenShell(tmp_path / "sandbox-fs")
    monkeypatch.setattr(base_module, "_run", shell)
    monkeypatch.setattr(base_module, "_spawn", shell.spawn)
    monkeypatch.setattr(
        sandbox_module, "_check", lambda job: {"model": True, "knowledge_base": "KbStoreError: Cannot reach Qdrant"}
    )
    data = write_benchmark(tmp_path / "b.jsonl")
    run_dir = tmp_path / "run"
    with pytest.raises(SystemExit) as code:
        cli.main([*_run_args(data, run_dir), "--sandbox", "sbx"])
    assert code.value.code == 2
    assert "Cannot reach Qdrant" in capsys.readouterr().err
    assert not run_dir.exists()
