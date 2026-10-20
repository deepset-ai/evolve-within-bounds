# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Judging PrimeVul functions inside the NVIDIA OpenShell sandbox (`security_agent.sandbox`).

One job per function: the agent file and the user message go in, the function's record comes back (`judge`). The
task's id, its pair, its labels and the benchmark file stay on the host. Inside, `security-agent primevul sandbox
run-job` loads the agent and judges the function with `security_agent.primevul.measure.judge`, as the host does
without a sandbox; the record's seconds are the judgement's, without loading the agent.

The agent file is rewritten for the sandbox (`OpenShell.agent`); nothing else in it changes:
- the model, for the agent and the knowledge-base sub-agent: the managed inference route, `https://inference.local/v1`;
- the knowledge base: Qdrant on the host, at `http://host.openshell.internal:6333`. The sandbox's policy allows only
  reads there (sandbox/security-triage/policy-additions.yaml), and Qdrant must listen on OpenShell's bridge
  (serving/qdrant/). The retrieval models are in the sandbox image.

The knowledge-base tool reports a missing knowledge base instead of failing, so a run would go on without it. Before
a run, `check` therefore asks the sandbox once whether the model answers and the knowledge base returns documents.
"""

from __future__ import annotations

import copy
import time
from pathlib import Path
from typing import Any

from security_agent import sandbox as base
from security_agent.sandbox import SandboxError

RUN_JOB = ("security-agent", "primevul", "sandbox", "run-job")  # the command inside the sandbox
QDRANT_URL = "http://host.openshell.internal:6333"  # the host's Qdrant, as the sandbox reaches it
KB_TOOL = "security_agent.knowledge_base.search.SecurityKbSearch"
CHECK_QUERY = "write past the end of a heap buffer"


def kb_tools(config: dict[str, Any]) -> list[dict[str, Any]]:
    """The init parameters of each knowledge-base tool in an agent file, to read or change in place."""
    return [
        tool["data"]["component"]["init_parameters"]
        for tool in config["init_parameters"].get("tools") or []
        if ((tool.get("data") or {}).get("component") or {}).get("type") == KB_TOOL
    ]


class OpenShell(base.OpenShell):
    """
    The sandbox, with PrimeVul's jobs: judging one function, and checking what the agent reaches.

    :param qdrant_url: the knowledge base's Qdrant, as the sandbox reaches it.
    """

    command = RUN_JOB

    def __init__(self, name: str, *, qdrant_url: str = QDRANT_URL, **kwargs: Any) -> None:
        super().__init__(name, **kwargs)
        self.qdrant_url = qdrant_url

    def agent(self, config: dict[str, Any]) -> dict[str, Any]:
        """An agent file as it runs in the sandbox: the model through the inference route, Qdrant on the host."""
        config = copy.deepcopy(config)
        config["init_parameters"]["chat_generator"]["init_parameters"]["api_base_url"] = self.inference_url
        for params in kb_tools(config):
            params["qdrant_url"] = self.qdrant_url
            if params.get("llm_base_url"):
                params["llm_base_url"] = self.inference_url
        return config

    def judge(self, config: dict[str, Any], question: str) -> dict[str, Any]:
        """One function's record, judged in the sandbox. Raises `SandboxError` when the job fails, not the agent."""
        result = self.run_job({"kind": "judge", "agent": self.agent(config), "question": question}, {})
        if "error" in result:
            raise SandboxError(result["error"])
        return result["record"]

    def check(self, config: dict[str, Any]) -> dict[str, Any]:
        """
        Whether the agent reaches the model and the knowledge base from inside the sandbox.

        Returns what the check found; raises `SandboxError` naming what the agent cannot reach.
        """
        result = self.run_job({"kind": "check", "agent": self.agent(config)}, {})
        if "error" in result:
            raise SandboxError(result["error"])
        problems = []
        if not result["model"]:
            problems.append(
                f"the model does not answer at {self.inference_url}: is the model server listening on OpenShell's "
                "bridge? (sandbox/sandbox.sh status)"
            )
        if result.get("knowledge_base"):
            reason = result["knowledge_base"]
            hint = (
                "the sandbox's policy refused the request (sandbox/security-triage/policy-additions.yaml)"
                if "blocked" in reason
                else "is Qdrant listening on OpenShell's bridge? (sandbox/sandbox.sh status)"
            )
            problems.append(f"the knowledge base at {self.qdrant_url} does not answer ({reason}); {hint}")
        elif result.get("documents") == 0:
            problems.append(f"the knowledge base at {self.qdrant_url} is empty: hatch run primevul:kb build")
        if problems:
            raise SandboxError(f"in the sandbox {self.name}, " + "; ".join(problems))
        return result


# -- inside the sandbox ----------------------------------------------------------------------------


def _judge(job: dict[str, Any]) -> dict[str, Any]:
    from security_agent.primevul import agent as agents
    from security_agent.primevul.measure import judge, sub_agent_trace_taker

    started = time.monotonic()
    try:
        agent = agents.load_agent(job["agent"])
        agent.warm_up()
        started = time.monotonic()
        record = judge(agent, job["question"], sub_agent_trace_taker())
    except Exception as exc:  # the agent's failure, recorded as on the host
        record = {"answer": "", "error": f"{type(exc).__name__}: {exc}", "verdict": {"parse_error": True}}
    record["seconds"] = round(time.monotonic() - started, 1)
    return {"record": record}


def _check(job: dict[str, Any]) -> dict[str, Any]:
    from security_agent.generator import server_answers
    from security_agent.knowledge_base.search import SecurityKbSearch

    generator = job["agent"]["init_parameters"]["chat_generator"]["init_parameters"]
    found: dict[str, Any] = {"model": server_answers(generator["api_base_url"], generator["model"])}
    for params in kb_tools(job["agent"]):
        try:
            found["documents"] = len(SecurityKbSearch(**params).retrieve(CHECK_QUERY, top_k=1))
        except Exception as exc:  # unreachable, not built, or the models do not load
            found["knowledge_base"] = f"{type(exc).__name__}: {exc}"[-600:]
    return found


def _execute(job: dict[str, Any], root: Path) -> dict[str, Any]:  # noqa: ARG001 - the job has no files
    kind = job["kind"]
    if kind == "judge":
        return _judge(job)
    if kind == "check":
        return _check(job)
    raise ValueError(f"unknown job kind {kind!r}")


def run_job(job_dir: Path, out: Path) -> None:
    """Run one uploaded job and write its result to `out`; the job directory is removed. A failure is a result too."""
    base.run_job(job_dir, out, _execute)
