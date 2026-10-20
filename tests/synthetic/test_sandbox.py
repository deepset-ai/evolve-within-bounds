# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fake_vllm import FakeVllm
from helpers import SEED, STORE, UTIL, FakeBenchmark, OnePairBench, candidate, model
from test_agent import CHECK, SEARCH, _with_code

import security_agent.synthetic.sandbox as sandbox_module
from security_agent.synthetic.agent import AgentScanner
from security_agent.synthetic.bench.runner import run
from security_agent.synthetic.examples import Examples
from security_agent.synthetic.sandbox import OpenShell, SandboxError, SandboxScanner, run_job


class _Finished:
    def __init__(self, returncode):
        self.returncode = returncode

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        pass


class _Hung:
    """An exec that never starts its command and never returns, until killed."""

    returncode = None

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("openshell", timeout)
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


class FakeOpenShell:
    """The `openshell` CLI (0.0.106) against a directory standing in for the sandbox's filesystem. Like the real one, it
    uploads a directory into `<dest>/<its name>` and downloads a file into a directory. The first `fail_execs` job
    executions fail; the first `hang_execs` hang."""

    def __init__(self, root: Path, fail_execs: int = 0, hang_execs: int = 0):
        self.root, self.fail_execs, self.hang_execs = root, fail_execs, hang_execs
        self.calls: list[list[str]] = []

    def spawn(self, args, stderr):
        if self.hang_execs:
            self.hang_execs -= 1
            self.calls.append(args)
            return _Hung()
        done = self(args, 0)
        stderr.write(done.stderr)
        return _Finished(done.returncode)

    def path(self, remote: str) -> Path:
        if remote.startswith(str(self.root)):  # the deployed agent, as a job sees it
            return Path(remote)
        assert remote.startswith("/sandbox/")
        return self.root / remote.removeprefix("/sandbox/")

    def __call__(self, args, timeout_s):
        self.calls.append(args)
        assert args[:2] == ["openshell", "sandbox"]
        verb, rest = args[2], args[3:]
        if verb == "upload":
            assert rest[0] == "--no-git-ignore" and rest[1] == "sbx"
            local, dest = Path(rest[2]), self.path(rest[3])
            shutil.copytree(local, dest / local.name)
        elif verb == "download":
            source, dest = self.path(rest[1]), Path(rest[2])
            if not source.is_file():
                return subprocess.CompletedProcess(args, 1, "", "no such file")
            shutil.copy2(source, dest / source.name)
        elif verb == "exec":
            command = rest[rest.index("--") + 1 :]
            if tuple(command[:4]) == sandbox_module.RUN_JOB:
                if self.fail_execs:
                    self.fail_execs -= 1
                    return subprocess.CompletedProcess(args, 255, "", "relay closed")
                run_job(self.path(command[command.index("--job") + 1]), self.path(command[command.index("--out") + 1]))
            elif command[:2] == ["sh", "-c"]:  # the host's check on a running job
                result, started = re.findall(r'"([^"]+)"', command[2])[:2]
                state = "done" if self.path(result).exists() else "running 0" if self.path(started).exists() else ""
                return subprocess.CompletedProcess(args, 0, state + "\n", "")
            elif command[:2] == ["rm", "-rf"]:
                for remote in command[2:]:
                    target = self.path(remote)
                    shutil.rmtree(target) if target.is_dir() else target.unlink(missing_ok=True)
            else:
                raise AssertionError(command)
        return subprocess.CompletedProcess(args, 0, "", "")

    def leftovers(self) -> list[str]:
        return sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*") if p.is_file())


@pytest.fixture(autouse=True)
def _deployed_path(tmp_path, monkeypatch):
    """Inside the fake sandbox, the deployed agent lives under the fake's root."""
    monkeypatch.setattr(sandbox_module, "DEPLOYED", str(tmp_path / "sandbox-fs" / ".security-triage" / "deployed"))


def _sandbox(tmp_path, url, **fake):
    shell = FakeOpenShell(tmp_path / "sandbox-fs", **fake)
    return OpenShell("sbx", inference_url=url, runner=shell, spawner=shell.spawn), shell


def test_scans_in_the_sandbox_match_scans_on_the_host(tmp_path):
    files = {"src/pkg/store.py": STORE, "src/pkg/util.py": UTIL}
    with FakeVllm() as server:
        host = run(
            FakeBenchmark(tmp_path / "a", n=1, files=files),
            AgentScanner(SEED, model_config=model(server.base_url)),
            tmp_path / "host",
            log=lambda *_: None,
        )
        sandbox, shell = _sandbox(tmp_path, server.base_url)
        scanner = SandboxScanner(AgentScanner(SEED, model_config=model("http://127.0.0.1:1/v1")), sandbox)
        inside = run(
            FakeBenchmark(tmp_path / "b", n=1, files=files), scanner, tmp_path / "sandboxed", log=lambda *_: None
        )
    assert host.complete == inside.complete == 1
    predictions = [
        json.loads((tmp_path / d / "predictions.jsonl").read_text())["findings"] for d in ("host", "sandboxed")
    ]
    assert predictions[0] == predictions[1] and predictions[0][0]["line_start"] == 9
    manifest = json.loads((tmp_path / "sandboxed" / "manifest.json").read_text())
    assert manifest["scanner"]["sandbox"] == "sbx" and manifest["scanner"]["name"] == "agent"
    assert shell.leftovers() == []  # jobs and results are removed
    uploads = [c for c in shell.calls if c[2] == "upload"]
    assert len(uploads) == 1 and "instance-" not in json.dumps(uploads)  # the instance id never reaches the sandbox


def test_the_optimizers_code_runs_in_the_sandbox(tmp_path):
    bench = OnePairBench(tmp_path)
    draft = candidate(
        tmp_path,
        _with_code,
        {"search.py": SEARCH, "check.py": CHECK, "hunt.py": 'KIND = "step"\n\n\ndef run(ctx):\n    pass\n'},
    )
    with FakeVllm() as server:
        sandbox, shell = _sandbox(tmp_path, server.base_url)
        assert sandbox.contract_test(draft) == []
        examples = Examples(
            {"hvbench": ["pair-x"]},
            lambda b, iid: None,
            bench_loader=lambda name: bench,
            model=model("http://127.0.0.1:1/v1"),
            sandbox=sandbox,
        )
        out = json.loads(examples(draft / "tools", "search", "hvbench/pair-x", {"pattern": "requests"}))
        assert out["ok"] and "src/fetch.py:5:" in out["vulnerable"]["output"]
        trial = json.loads(examples.trial(draft, "hvbench/pair-x"))
        assert trial["ok"] and trial["vulnerable"]["agent"]["tool_calls"]["search"] == 1
    assert shell.leftovers() == []
    broken = candidate(tmp_path, None, None, "broken")
    (broken / "pipeline.yaml").write_text("components: [")
    assert "failed in the sandbox" in sandbox.contract_test(broken)[0]


def test_a_failed_exec_is_retried_and_then_reported(tmp_path):
    files = {"src/pkg/store.py": STORE, "src/pkg/util.py": UTIL}
    with FakeVllm() as server:
        sandbox, shell = _sandbox(tmp_path, server.base_url, fail_execs=1)
        scanner = SandboxScanner(AgentScanner(SEED, model_config=model("http://127.0.0.1:1/v1")), sandbox)
        assert (
            run(
                FakeBenchmark(tmp_path / "a", n=1, files=files), scanner, tmp_path / "once", log=lambda *_: None
            ).complete
            == 1
        )
        shell.fail_execs = 2
        summary = run(FakeBenchmark(tmp_path / "b", n=1, files=files), scanner, tmp_path / "twice", log=lambda *_: None)
    assert summary.incomplete == 1
    report = json.loads((tmp_path / "twice" / "reports.jsonl").read_text())
    assert "relay closed" in report["error"] and shell.leftovers() == []


def test_a_scan_that_fails_inside_raises_on_the_host(tmp_path):
    sandbox, _ = _sandbox(tmp_path, "http://127.0.0.1:1/v1")
    directory = candidate(tmp_path)
    scanner = SandboxScanner(AgentScanner(directory, model_config=model("http://127.0.0.1:1/v1")), sandbox)
    (directory / "pipeline.yaml").write_text("components: [")  # broken after the host checked it
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "a.py").write_text("x = 1\n")
    from security_agent.synthetic.staging import stage

    staged = stage(tmp_path / "repo")
    with pytest.raises(SandboxError, match="ParserError"):
        scanner.scan(staged)
    staged.cleanup()


def test_the_cli_runs_a_job(tmp_path):
    from security_agent.cli import main

    job = tmp_path / "job"
    shutil.copytree(SEED, job / "candidate")
    (job / "job.json").write_text(json.dumps({"kind": "contract", "code_version": sandbox_module.code_version()}))
    with pytest.raises(SystemExit) as code:
        main(["synthetic", "sandbox", "run-job", "--job", str(job), "--out", str(tmp_path / "out.json")])
    assert (
        code.value.code == 0
        and json.loads((tmp_path / "out.json").read_text()) == {"problems": []}
        and not job.exists()
    )


def test_a_deployed_agent_scans_repositories(tmp_path, monkeypatch):
    import yaml

    import security_agent.synthetic.cli as synthetic_cli
    from security_agent import cli

    shell = FakeOpenShell(tmp_path / "sandbox-fs")
    monkeypatch.setattr(sandbox_module, "_run", shell)
    monkeypatch.setattr(sandbox_module, "_spawn", shell.spawn)
    repo = tmp_path / "repo"
    for rel, text in {"src/pkg/store.py": STORE, "src/pkg/util.py": UTIL}.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    with FakeVllm() as server:
        (tmp_path / "config").mkdir()
        (tmp_path / "config" / "model.yaml").write_text(yaml.safe_dump(model(server.base_url)))
        monkeypatch.setattr(
            synthetic_cli, "load_yaml", lambda name: yaml.safe_load((tmp_path / "config" / name).read_text())
        )
        monkeypatch.setattr(OpenShell, "model", lambda self, m: m)  # the fake server stands in for the inference route
        with pytest.raises(SystemExit) as code:
            cli.main(["synthetic", "scan", str(repo), "--sandbox", "sbx", "--out", str(tmp_path / "none.json")])
        assert code.value.code == 2  # nothing deployed yet
        assert not list((tmp_path / "sandbox-fs").rglob("*.json"))
        with pytest.raises(SystemExit) as code:
            cli.main(
                [
                    "synthetic",
                    "sandbox",
                    "deploy",
                    "--sandbox",
                    "sbx",
                    "--candidate",
                    str(SEED),
                    "--approved-by",
                    "a reviewer",
                    "--yes",
                ]
            )
        assert code.value.code == 0
        approval = json.loads(next((tmp_path / "sandbox-fs").rglob("approval.json")).read_text())
        assert approval["approved_by"] == "a reviewer" and approval["source"] == str(SEED)
        with pytest.raises(SystemExit) as code:
            cli.main(["synthetic", "scan", str(repo), "--sandbox", "sbx", "--out", str(tmp_path / "result.json")])
    assert code.value.code == 0
    result = json.loads((tmp_path / "result.json").read_text())
    assert [(f["path"], f["line_start"]) for f in result["findings"]] == [("src/pkg/store.py", 9)]


def test_a_job_whose_exec_hangs_is_retried(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox_module, "POLL_S", 0.01)
    monkeypatch.setattr(sandbox_module, "START_TIMEOUT_S", 0.05)
    sandbox, shell = _sandbox(tmp_path, "http://127.0.0.1:1/v1", hang_execs=1)
    assert sandbox.contract_test(SEED) == []
    jobs = [c for c in shell.calls if "run-job" in c]
    assert len(jobs) == 2 and shell.leftovers() == []
    sandbox, shell = _sandbox(tmp_path / "2", "http://127.0.0.1:1/v1", hang_execs=2)
    with pytest.raises(SandboxError, match="did not start"):
        sandbox.contract_test(SEED)


def test_the_watchdog_outlasts_an_exec_that_returns_early(monkeypatch):
    monkeypatch.setattr(sandbox_module, "POLL_S", 0.01)
    sandbox = OpenShell("sbx", runner=lambda args, timeout: None, spawner=lambda args, err: _Finished(255))
    states = iter(["running", "running", "done"])
    monkeypatch.setattr(sandbox, "_state", lambda result, started: next(states))
    assert sandbox._run_job("job", "result", "started").startswith("exit 255")  # it waited for the result
    states = iter(["running", "stalled"])
    with pytest.raises(SandboxError, match="stopped without a result"):
        sandbox._run_job("job", "result", "started")


@pytest.mark.parametrize(
    "stdout, state", [("done\n", "done"), ("running 12\n", "running"), ("running 500\n", "stalled"), ("\n", "")]
)
def test_the_state_check(stdout, state):
    sandbox = OpenShell("sbx", runner=lambda args, timeout: subprocess.CompletedProcess(args, 0, stdout, ""))
    assert sandbox._state("result", "started") == state


def test_a_sandbox_with_other_code_refuses_jobs(tmp_path):
    job = tmp_path / "job"
    shutil.copytree(SEED, job / "candidate")
    (job / "job.json").write_text(json.dumps({"kind": "contract", "code_version": "0123456789abcdef"}))
    run_job(job, tmp_path / "out.json")
    assert "recreate the sandbox" in json.loads((tmp_path / "out.json").read_text())["error"]
