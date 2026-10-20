# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The synthetic benchmark's work inside the NVIDIA OpenShell sandbox (`security_agent.sandbox`).

With a sandbox, the host never runs a candidate's code. A job's files are the candidate (or one code file) and the
staged repository; inside, `security-agent synthetic sandbox run-job` stages the repository again (fresh metadata, a
random path) and deletes the upload before the job sees it.

The jobs:
- `scan`: one repository with a candidate (`SandboxScanner`; `bench run --sandbox` and the loop's measurements), or
  with the deployed agent (`scan --sandbox`);
- `tool` / `step`: one of the optimizer's code files on one repository (the optimizer's `run_tool`);
- `contract`: the contract test of a draft (the optimizer's `validate_candidate`).

**Deployment.** After a person approves a candidate, `sandbox deploy` installs it in the sandbox (`DEPLOYED`), with
a record of the approval. `scan --sandbox NAME REPO` then scans with it.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from security_agent import sandbox as base
from security_agent.sandbox import SandboxError
from security_agent.synthetic.schema import ScanResult
from security_agent.synthetic.staging import StagedRepo, stage

DEPLOYED = "/sandbox/.security-triage/deployed"  # the approved agent: candidate/ and approval.json
RUN_JOB = ("security-agent", "synthetic", "sandbox", "run-job")  # the command inside the sandbox


class OpenShell(base.OpenShell):
    """The sandbox, with the synthetic benchmark's jobs: scans, the optimizer's code, the contract test, deployment."""

    command = RUN_JOB

    def run_member(
        self,
        path: Path,
        kind: str,
        staged: StagedRepo,
        model: dict[str, Any],
        arguments: dict | None = None,
        reported: list[dict] | None = None,
    ) -> dict[str, Any]:
        """`security_agent.synthetic.examples.run_member`, in the sandbox."""
        job = {
            "kind": kind,
            "model": self.model(model),
            "code": Path(path).name,
            "arguments": arguments,
            "reported": reported,
        }
        result = self.run_job(job, {f"code/{Path(path).name}": Path(path), "repo": staged.root})
        if "error" in result:
            return {"ok": False, "error": result["error"]}
        return result["member"]

    def deploy(self, directory: Path, approval: dict[str, Any]) -> None:
        """Install an approved candidate in the sandbox, replacing the one deployed before."""
        with tempfile.TemporaryDirectory(prefix="security-agent-deploy-") as tmp:
            local = Path(tmp) / "deployed"
            shutil.copytree(directory, local / "candidate", ignore=shutil.ignore_patterns("__pycache__"))
            (local / "approval.json").write_text(json.dumps(approval, indent=1), encoding="utf-8")
            self.exec("rm", "-rf", DEPLOYED, timeout_s=120)
            self.upload(local, str(Path(DEPLOYED).parent))

    def scan_deployed(self, repo: StagedRepo, model: dict[str, Any]) -> ScanResult:
        """Scan one repository with the deployed agent."""
        result = self.run_job({"kind": "scan", "deployed": True, "model": self.model(model)}, {"repo": repo.root})
        if "error" in result:
            raise SandboxError(result["error"])
        return ScanResult.model_validate(result["scan"])

    def contract_test(self, directory: Path) -> list[str]:
        """`security_agent.synthetic.agent.contract_test`, in the sandbox."""
        result = self.run_job({"kind": "contract"}, {"candidate": Path(directory)})
        if "error" in result:
            return [f"the contract test failed in the sandbox: {result['error']}"]
        return result["problems"]


class SandboxScanner:
    """An `AgentScanner` whose scans run in the sandbox. Same name and description, plus the sandbox's name."""

    def __init__(self, inner: Any, sandbox: OpenShell) -> None:
        self.inner, self.sandbox = inner, sandbox
        self.name = inner.name

    def describe(self) -> dict[str, Any]:
        """The inner scanner's description, with the sandbox's name."""
        return {**self.inner.describe(), "sandbox": self.sandbox.name}

    def scan(self, repo: StagedRepo) -> ScanResult:
        """Scan one staged repository in the sandbox."""
        job = {"kind": "scan", "model": self.sandbox.model(self.inner.model)}
        result = self.sandbox.run_job(job, {"candidate": self.inner.candidate_dir, "repo": repo.root})
        if "error" in result:
            raise SandboxError(result["error"])
        return ScanResult.model_validate(result["scan"])


# -- inside the sandbox ----------------------------------------------------------------------------


def _execute(job: dict[str, Any], root: Path) -> dict[str, Any]:
    kind = job["kind"]
    if kind == "contract":
        from security_agent.synthetic.agent import contract_test

        return {"problems": contract_test(root / "candidate")}
    staged = stage(root / "repo")
    shutil.rmtree(root / "repo")  # the scan sees only the fresh copy
    try:
        if kind == "scan":
            from security_agent.synthetic.agent import AgentScanner

            directory = Path(DEPLOYED) / "candidate" if job.get("deployed") else root / "candidate"
            if not directory.is_dir():
                raise FileNotFoundError(
                    f"no candidate at {directory}" + (": nothing is deployed" if job.get("deployed") else "")
                )
            return {"scan": AgentScanner(directory, model_config=job["model"]).scan(staged).model_dump(mode="json")}
        if kind in ("tool", "step"):
            from security_agent.synthetic.examples import run_member

            return {
                "member": run_member(
                    root / "code" / job["code"],
                    kind,
                    str(staged.root),
                    list(staged.files),
                    job["model"],
                    job.get("arguments"),
                    job.get("reported"),
                )
            }
        raise ValueError(f"unknown job kind {kind!r}")
    finally:
        staged.cleanup()


def run_job(job_dir: Path, out: Path) -> None:
    """Run one uploaded job and write its result to `out`; the job directory is removed. A failure is a result too."""
    base.run_job(job_dir, out, _execute)
