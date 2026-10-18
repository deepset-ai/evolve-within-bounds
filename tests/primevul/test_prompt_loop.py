# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""The prompt loop: PrimeVul's task on the shared loop, with a fake agent and a scripted optimizer."""

import json
import shutil
from pathlib import Path

import pytest
import yaml
from haystack.dataclasses import ChatMessage

from security_agent.optimize.leakage import Leakage
from security_agent.optimize.loop import Experiment
from security_agent.primevul.task import PrimeVulTask, check_candidate, pair_names, render

pytest.importorskip("haystack_integrations.agent_pack")

SEED = Path(__file__).resolve().parents[2] / "agents" / "primevul" / "seed"
HINT = "Weigh what the patch would add."
BENIGN = json.dumps({"is_vulnerable": False, "cwe": None, "vulnerable_lines": [], "rationale": "bounded"})
VULNERABLE = json.dumps({"is_vulnerable": True, "cwe": "CWE-787", "vulnerable_lines": [1], "rationale": "unbounded"})
USAGE = {"prompt_tokens": 1000, "completion_tokens": 200, "prompt_tokens_details": {"cached_tokens": 600}}


def write_train(path: Path, n: int = 6) -> Path:
    rows = []
    for k in range(n):
        body = f"int handle_record_{k}(char *s) {{ char b[8]; copy_name_{k}(b, s); return {k}; }}"
        fixed = body.replace("copy_name", "checked_copy").replace("(b, s)", "(b, s, sizeof b)")
        for code, vulnerable in ((body, True), (fixed, False)):
            rows.append(
                {
                    "id": f"t{k}-{'v' if vulnerable else 'f'}",
                    "code": code,
                    "lang": "c",
                    "gold_is_vulnerable": vulnerable,
                    "gold_cwe": "CWE-787" if vulnerable else None,
                    "pair_id": f"p{k}",
                    "split": "train",
                }
            )
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


class APIConnectionError(Exception):
    """Named like the OpenAI client's error, which the measurement counts as a model-server outage."""


class FakeAgent:
    """Calls every function vulnerable, unless its prompt asks it to weigh the patch; `outage` fails p0's twin."""

    def __init__(self, config, outage):
        self.prompt = config["init_parameters"]["system_prompt"]
        self.outage = outage

    def warm_up(self):
        pass

    def run(self, messages):
        question = messages[0].text
        if "checked_copy_0(" in question and self.outage:
            self.outage.pop()
            raise APIConnectionError("Connection error.")
        patched = "checked_copy" in question
        answer = BENIGN if patched and HINT in self.prompt else VULNERABLE
        reply = ChatMessage.from_assistant(answer, meta={"usage": USAGE})
        return {"messages": [messages[0], reply], "last_message": reply, "step_count": 1}


def make_task(tmp_path, outage=None):
    data = write_train(tmp_path / "train.jsonl")
    outage = outage if outage is not None else []
    return PrimeVulTask(
        SEED, data=data, concurrency=1, load_agent=lambda config: FakeAgent(config, outage), log=lambda *_: None
    )


def edit_prompt(directory: Path, extra: str) -> None:
    path = directory / "agent.yaml"
    text = path.read_text()
    anchor = "    - Base your verdict only on the code shown."
    assert text.count(anchor) == 1
    path.write_text(text.replace(anchor, f"{anchor} {extra}"))


def test_check_candidate_holds_everything_but_the_texts_and_budgets(tmp_path):
    reference = yaml.safe_load((SEED / "agent.yaml").read_text())
    draft = tmp_path / "draft"
    shutil.copytree(SEED, draft)
    assert check_candidate(draft, reference) == []

    config = yaml.safe_load((draft / "agent.yaml").read_text())
    config["init_parameters"]["max_agent_steps"] = 10
    config["init_parameters"]["chat_generator"]["init_parameters"]["generation_kwargs"]["max_tokens"] = 12000
    config["init_parameters"]["tools"][0]["data"]["description"] = "Ask about CWE classes."
    (draft / "agent.yaml").write_text(yaml.safe_dump(config))
    assert check_candidate(draft, reference) == []

    config["init_parameters"]["chat_generator"]["init_parameters"]["generation_kwargs"]["temperature"] = 0.7
    config["init_parameters"]["chat_generator"]["init_parameters"]["model"] = "another"
    config["init_parameters"]["tools"][0]["data"]["component"]["init_parameters"]["top_k"] = 50
    config["init_parameters"]["system_prompt"] = "Answer with is_vulnerable only."
    (draft / "agent.yaml").write_text(yaml.safe_dump(config))
    problems = check_candidate(draft, reference)
    assert any("temperature" in p for p in problems)
    assert any("chat_generator.model" in p for p in problems)
    assert any("component must stay" in p for p in problems)
    assert any("missing: cwe, vulnerable_lines, rationale" in p for p in problems)

    (draft / "notes.txt").write_text("x")
    assert check_candidate(draft, reference)[0].startswith("a candidate is one file")


def test_measure_counts_pairs_findings_cost_and_outages(tmp_path):
    task = make_task(tmp_path, outage=[1])
    m = task.measure(SEED, [{"primevul": ["p0", "p1"]}, {"primevul": ["p2"]}], tmp_path / "m", label="reference")
    assert m.pairs == 3 and m.right == 0 and m.instances == 6
    assert m.findings == 5  # p0's patched twin failed with a server error, the other five were called vulnerable
    assert m.incomplete == 1
    assert m.cost == {"prompt_tokens": 5000, "completion_tokens": 1000, "calls": 5, "cached_tokens": 3000}
    assert {d["labels"][0] for d in m.digests} == {"missed_fix", "parse_error"}
    text = render(next(d for d in m.digests if d["labels"] == ["missed_fix"]))
    assert "missed_fix" in text and "```diff" in text and "checked_copy" in text

    assert task.spoiled(m) == 1  # the outage's record is dropped and measured again
    again = task.measure(SEED, [{"primevul": ["p0", "p1", "p2"]}], tmp_path / "m", label="reference")
    assert again.incomplete == 0 and again.findings == 6


def test_leakage_material_is_training_code_and_pair_names(tmp_path):
    task = make_task(tmp_path)
    shown = task.training_material({"primevul": ["p0", "p1"]})
    assert "copy_name_0" in shown["names"] and "handle_record_1" in shown["names"]
    assert all("strcpy" not in n for n in shown["names"])
    leakage = Leakage()
    leakage.add(shown)
    assert leakage.check("Look for copy_name_0 calls.") == ["training function name 'copy_name_0'"]
    assert any("code copied" in h for h in leakage.check("e.g. char b[8]; copy_name_9(b, s); return 0; }"))
    assert leakage.check("A bounded copy that passes the destination size is a fix.") == []
    assert pair_names(task.pairs) == sorted(pair_names(task.pairs))


def test_the_loop_improves_the_prompt_and_refuses_a_leak(tmp_path):
    task = make_task(tmp_path)

    def propose(ws, context, trajectory):
        assert "primevul: p0, p1" in context[0]
        if not task_state:
            assert "missed_fix" in context[2]
            edit_prompt(ws.draft, "Mention copy_name_0.")
            errors = json.loads(ws.validate_candidate())["errors"]
            assert errors[0].startswith("leakage: training function name 'copy_name_0'.")
            task_state.append("leak refused")
            shutil.copy(SEED / "agent.yaml", ws.draft / "agent.yaml")
            edit_prompt(ws.draft, HINT)
            assert json.loads(ws.validate_candidate())["valid"], ws.validation_failures
            ws.submit_candidate("weigh the patch", ws.revision)
            return ws.submitted, {"seconds": 1.0}
        ws.finish("nothing left to try")
        return None, {"seconds": 1.0}

    task_state: list[str] = []
    experiment = Experiment(
        tmp_path / "opt-1",
        config={"iterations": 3, "gpu_hours": 10, "seed": 1, "rules": {"max_findings_per_repo": 1}},
        train={"primevul": [f"p{k}" for k in range(6)]},
        reference=SEED,
        proposer=propose,
        task=task,
        log=lambda *_: None,
    )
    decision = experiment.run()
    [outcome] = experiment.outcomes
    assert task_state == ["leak refused"]
    assert outcome.gates == [] and outcome.score.right == 6 and experiment.ref.right == 0
    assert decision["best"] == outcome.candidate_id
    assert (Path(decision["best_directory"]) / "agent.yaml").is_file()
    assert decision["stop_reason"].startswith("the optimizer finished")


def test_read_reasoning_shows_the_function_and_the_record(tmp_path):
    task = make_task(tmp_path)
    m = task.measure(SEED, [{"primevul": ["p0"]}], tmp_path / "m", label="reference")
    reader = task.workspace_options({"primevul": ["p0"]}, lambda: m, lambda shown: None)["reasoning_reader"]
    text = reader("primevul/p0", "fixed")
    assert "checked_copy_0(b, s, sizeof b)" in text and '"verdict": "vulnerable"' in text
    assert "not a training pair" in reader("primevul/p9")
