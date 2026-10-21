# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

import pytest
import yaml
from fake_vllm import FakeVllm
from helpers import SEED, PairBenchmark, model

from security_agent.optimize.leakage import Leakage
from security_agent.optimize.loop import Experiment, Rules, gate_failures, mcnemar_one_sided, split_halves
from security_agent.optimize.measurement import Measurement
from security_agent.optimize.splits import pairs, subsample
from security_agent.synthetic.agent import check_candidate, contract_test
from security_agent.synthetic.config import load_yaml, resolve
from security_agent.synthetic.measure import drop_outage_instances, measure
from security_agent.synthetic.task import SyntheticTask, split

# -- leakage ---------------------------------------------------------------------------------------

SHOWN = {
    "paths": ["src/custom_components/request_context/token_reader.py"],
    "repositories": ["synth-01-request-context"],
    "titles": ["Token claims are read without verifying the signature"],
    "code": ['        claims = jwt.decode(token, options={"verify_signature": False})'],
}


@pytest.mark.parametrize(
    "text, hit",
    [
        ("Look closely at token_reader.py around line 42.", "training file name"),
        ("Repositories like synth-01-request-context forward URLs.", "training repository name"),
        ("Flag code where token claims are read without verifying the signature.", "pair title"),
        ('e.g. claims = jwt.decode(token, options={"verify_signature": False})', "code copied"),
    ],
)
def test_leakage_hits(text, hit):
    leakage = Leakage()
    leakage.add(SHOWN)
    assert any(hit in h for h in leakage.check(text)), leakage.check(text)


def test_generic_security_knowledge_is_not_leakage():
    leakage = Leakage()
    leakage.add(SHOWN)
    text = (
        "A JWT must be verified before its claims are trusted: report decode calls that disable signature "
        "verification. Base URLs taken from init parameters are attacker-controlled (SSRF)."
    )
    assert leakage.check(text) == []


# -- rules -----------------------------------------------------------------------------------------


def test_mcnemar_and_halves():
    assert mcnemar_one_sided(4, 0) == pytest.approx(1 / 16)
    assert mcnemar_one_sided(6, 1) == pytest.approx(8 / 128)
    assert mcnemar_one_sided(0, 0) == 1.0
    halves = split_halves({"b": [f"p{i}" for i in range(9)]}, 1)
    assert len(halves[0]["b"]) == 5 and not set(halves[0]["b"]) & set(halves[1]["b"])
    assert halves == split_halves({"b": [f"p{i}" for i in range(9)]}, 1)


def test_gates_are_fixed_limits_per_repository():
    rules = Rules()
    seed = Measurement("seed", instances=72, findings=10, cost={"prompt_tokens": 1, "completion_tokens": 1})
    ok = Measurement(
        "ok", instances=72, findings=700, cost={"prompt_tokens": 3000 * 60 * 72, "completion_tokens": 110 * 60 * 72 * 4}
    )
    assert (
        gate_failures(ok, seed, rules, [], "repository") == []
    )  # 5 GPU-minutes and 9.7 findings per repository: within, however far above the seed
    big = Measurement(
        "big",
        instances=72,
        findings=800,
        incomplete=1,
        tool_errors=4,
        cost={"prompt_tokens": 3000 * 60 * 72 * 7, "completion_tokens": 0},
    )
    assert gate_failures(big, seed, rules, ["training file name 'x.py'"], "repository") == [
        "leakage: training file name 'x.py'",
        "incomplete: 1 vs 0",
        "cost: 7.0 GPU-minutes per repository, above the limit of 6",
        "findings: 11.1 per repository, above the limit of 10",
        "tool_errors: the candidate's code failed on 4 of 72 instances",
    ]
    cached = Measurement(
        "cached",
        instances=1,
        cost={"prompt_tokens": 3000 * 60 * 7, "cached_tokens": 3000 * 60 * 7, "completion_tokens": 0},
    )
    assert (
        gate_failures(cached, seed, rules, [], "repository") == []
    )  # prompt tokens served from the prefix cache cost nothing


# -- the experiment, with a fake measurement and a scripted optimizer --------------------------------

TRAIN = {"hvbench": [f"p{i:02d}" for i in range(16)]}
# max_agent_steps -> the training pairs right. The seed (15) misses p00 and p01; 20 gets everything; 30 nothing.
RIGHT = {15: set(TRAIN["hvbench"][2:]), 20: set(TRAIN["hvbench"]), 30: set()}
EXPENSIVE = {25}  # 7 GPU-minutes per repository


class _TrainBench:
    def __init__(self, root):
        self.root = root
        (root / "data").mkdir(parents=True, exist_ok=True)
        rows = [
            {
                "pair_id": p,
                "repository": f"repo-{p}",
                "title": f"Planted defect number {p} in the request handler",
                "targets": [{"path": f"src/{p}.py", "role": "sink"}],
            }
            for p in TRAIN["hvbench"]
        ]
        (root / "data" / "pairs.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))


def _steps(directory):
    return yaml.safe_load((Path(directory) / "pipeline.yaml").read_text())["components"]["agent"]["init_parameters"][
        "max_agent_steps"
    ]


class _FakeTask(SyntheticTask):
    """The synthetic task with a scripted measurement: max_agent_steps decides which pairs come out right."""

    def __init__(self, seen, bench):
        super().__init__(
            model_config={"api_base_url": "http://127.0.0.1:1/v1", "model": "fake"}, bench_loader=lambda name: bench
        )
        self.seen = seen

    def measure(self, directory, parts, out_dir, *, label, abort=None):
        return _fake_measure(self.seen)(directory, parts, out_dir, label=label, abort=abort)


def _fake_measure(seen):
    def fake(directory, parts, out_dir, *, label, abort=None, digests=True):
        assert (Path(out_dir).parents[1] / "preregistration.json").is_file()
        steps = _steps(directory)
        seen.append((label, steps))
        right = RIGHT.get(steps, RIGHT[15])
        m = Measurement(label, seconds=60.0)
        for k, part in enumerate(parts, 1):
            for name, ids in part.items():
                for p in ids:
                    m.outcomes[f"{name}/{p}"] = [p in right, p in right]
                    m.instances += 2
                    if digests and p not in right:
                        m.digests.append(
                            {
                                "key": f"{name}/{p}",
                                "repository": f"repo-{p}",
                                "cwe": "CWE-89",
                                "title": "",
                                "labels": ["missed"],
                                "multi_file": False,
                                "targets": [],
                            }
                        )
            m.cost = {
                "prompt_tokens": 1000,
                "completion_tokens": 110 * 60 * 7 * m.instances if steps in EXPENSIVE else 500,
                "cached_tokens": 0,
            }
            if abort and k < len(parts) and abort(m):
                m.aborted = True
                break
        return m

    return fake


def _scripted_proposer(script):
    def propose(ws, context, trajectory):
        assert "## Failure digests of the draft" in context[2] and "hvbench: p00, p01" in context[0]
        step = script.pop(0)
        if step == "crash":
            raise RuntimeError("proposer crashed")
        if step == "finish":
            ws.finish("nothing left to try")
            return None, {"seconds": 1.0}
        ws.edit_file("pipeline.yaml", f"max_agent_steps: {_steps(ws.draft)}", f"max_agent_steps: {step}", ws.revision)
        assert json.loads(ws.validate_candidate())["valid"], ws.validation_failures
        ws.submit_candidate(f"try {step} steps", ws.revision)
        return ws.submitted, {"seconds": 1.0}

    return propose


def _experiment(tmp_path, script, seen, **config):
    return Experiment(
        tmp_path / "opt-1",
        config={"iterations": 5, "gpu_hours": 10, "seed": 7, **config},
        train=TRAIN,
        reference=SEED,
        proposer=_scripted_proposer(script),
        task=_FakeTask(seen, _TrainBench(tmp_path / "bench")),
        workspace_options={"check": check_candidate, "contract_check": contract_test},
        log=lambda *_: None,
    )


def test_experiment_gates_and_ranks(tmp_path):
    seen = []
    exp = _experiment(tmp_path, [30, 25, 20, "finish"], seen)
    decision = exp.run()
    assert [steps for _, steps in seen] == [15, 30, 25, 20]
    aborted, expensive, better = exp.outcomes
    assert aborted.gates[0].startswith("early_abort: 0 vs ") and list(aborted.score.outcomes) == [
        f"hvbench/{p}" for p in exp.halves[0]["hvbench"]
    ]
    assert expensive.gates == ["cost: 7.0 GPU-minutes per repository, above the limit of 6"]
    assert better.gates == [] and better.parent_id == exp.reference_id  # gated candidates never became the base
    assert decision["best"] == better.candidate_id and decision["stop_reason"].startswith("the optimizer finished")
    assert decision["train"]["discordant"] == [2, 0] and [c["eligible"] for c in decision["candidates"]] == [
        False,
        False,
        True,
    ]
    prereg = json.loads((tmp_path / "opt-1/preregistration.json").read_text())
    assert "GATES" in prereg["rules"] and prereg["train_halves"] == split_halves(TRAIN, 7)
    assert json.loads((tmp_path / "opt-1/decision.json").read_text())["best_directory"].endswith(
        "c003-" + better.candidate_id[:8]
    )


def test_experiment_refuses_a_candidate_that_names_training_answers(tmp_path):
    def leaky(ws, context, trajectory):
        first = (ws.draft / "prompts/system.md").read_text().splitlines()[0]
        assert json.loads(ws.edit_file("prompts/system.md", first, first + "\nCheck repo-p00 first.", ws.revision))[
            "ok"
        ]
        assert "training repository name 'repo-p00'" in json.loads(ws.validate_candidate())["errors"][0]
        ws.finish("refused")
        return None, {}

    exp = _experiment(tmp_path, [], [], iterations=1)
    exp.proposer = leaky
    assert exp.run()["best"] == exp.reference_id


def test_experiment_resumes_after_a_crash(tmp_path):
    seen = []
    with pytest.raises(RuntimeError, match="crashed"):
        _experiment(tmp_path, [20, "crash"], seen, iterations=3).run()
    second = _experiment(tmp_path, [16, "finish"], seen, iterations=3)
    decision = second.run()
    assert [label for label, _ in seen].count("reference") == 1  # not measured again
    assert len(second.outcomes) == 2 and second.outcomes[0].score.right == 16
    assert second.best_id == second.outcomes[0].candidate_id == decision["best"]  # 16 steps ranks below: the best stays
    assert second.outcomes[1].parent_id == second.outcomes[0].candidate_id


def test_experiment_stops_when_the_budget_is_spent(tmp_path):
    seen = []
    decision = _experiment(tmp_path, [], seen, gpu_hours=0.01).run()
    assert seen == [("reference", 15)] and decision["stop_reason"] == "GPU budget of 0.01 hours spent"


def test_outage_repair_rescans_what_an_outage_spoiled(tmp_path):
    seen = []
    exp = _experiment(tmp_path, [20, "finish"], seen)
    exp.run()
    outcome = exp.outcomes[0]
    run_dir = tmp_path / "opt-1" / "measure" / outcome.label / "hvbench-part1"
    (run_dir / "records").mkdir(parents=True)
    (run_dir / "records" / "i1.json").write_text(json.dumps({"agent": {"outage": True}, "components": []}))
    (run_dir / "reports.jsonl").write_text(json.dumps({"instance_id": "i1"}) + "\n")
    outcome.score.run_dirs = [str(run_dir)]
    seen.clear()
    exp._repair_outages()
    assert seen == [(outcome.label, 20)] and not (run_dir / "records" / "i1.json").exists()
    events = [json.loads(line)["type"] for line in (tmp_path / "opt-1/journal.jsonl").read_text().splitlines()]
    assert events[-2:] == ["remeasured", "rebest"]


def test_drop_outage_instances(tmp_path):
    (tmp_path / "records").mkdir()
    records = {
        "ok": {"agent": {"outage": False}, "components": []},
        "agent": {"agent": {"outage": True}, "components": []},
        "step": {"agent": {"outage": False}, "components": [{"calls": [{"outage": True}]}]},
    }
    for name, record in records.items():
        (tmp_path / "records" / f"{name}.json").write_text(json.dumps(record))
    (tmp_path / "reports.jsonl").write_text("".join(json.dumps({"instance_id": n}) + "\n" for n in records))
    assert drop_outage_instances(tmp_path) == 2
    assert [json.loads(line)["instance_id"] for line in (tmp_path / "reports.jsonl").read_text().splitlines()] == ["ok"]
    assert drop_outage_instances(tmp_path) == 0


# -- measuring, end to end through the scanner --------------------------------------------------


def test_measure_scores_parts_digests_failures_and_aborts(tmp_path):
    bench = PairBenchmark(tmp_path)
    parts = [{"pairbench": ["pair-a"]}, {"pairbench": ["pair-b"]}]
    with FakeVllm() as server:
        options = {"model_config": model(server.base_url), "log": lambda *_: None, "bench_loader": lambda name: bench}
        m = measure(SEED, parts, tmp_path / "m1", label="seed", **options)
        assert m.outcomes == {"pairbench/pair-a": [True, True], "pairbench/pair-b": [False, False]}
        assert [(d["key"], d["labels"]) for d in m.digests] == [("pairbench/pair-b", ["wrong_lines_near"])]
        assert m.cost["completion_tokens"] > 0 and m.instances == 4 and m.incomplete == 0 and m.findings == 2
        aborted = measure(SEED, parts, tmp_path / "m2", label="abort", abort=lambda m: True, **options)
    assert aborted.aborted and list(aborted.outcomes) == ["pairbench/pair-a"]


# -- the configuration ----------------------------------------------------------------------------


def test_loop_config_and_system_prompt():
    config = load_yaml("loop.yaml")
    train = subsample(pairs("train", split()), config["train_per_benchmark"], config["seed"])
    assert len(train["hvbench"]) == 24 and train == subsample(pairs("train", split()), 24, config["seed"])
    assert resolve(config["reference"]) == SEED
    assert set(Rules.__dataclass_fields__) == set(config["rules"])
    task = SyntheticTask(model_config={"api_base_url": "http://127.0.0.1:1/v1", "model": "fake"})
    prompt = task.system_prompt(task.prompt_values(config, train))
    assert (
        "$" not in prompt
        and "24 pairs (48 repositories)" in prompt
        and "`security_agent.synthetic.agent.CodeStep`" in prompt
    )
    assert "Allowed component types" in prompt  # the contract


def test_prepare_measures_the_start_and_run_resumes_from_it(tmp_path):
    seen = []
    prepared = _experiment(tmp_path, [], seen, iterations=1)
    m = prepared.prepare()
    assert m.right == 14 and [label for label, _ in seen] == ["reference"]
    assert not (tmp_path / "opt-1/decision.json").exists()  # prepared, not finished
    resumed = _experiment(tmp_path, [20], seen, iterations=1)
    decision = resumed.run()
    assert [label for label, _ in seen].count("reference") == 1  # measured once, in prepare
    assert decision["best"] == resumed.outcomes[0].candidate_id
