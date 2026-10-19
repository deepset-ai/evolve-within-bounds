# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The synthetic scan agents as a NeMo Gym agent server: our scanner, run on the repository a row names.

The scanner (`agent:` in the config, a candidate directory such as agents/synthetic/seed) is a pipeline around a
Haystack Agent, with its own tools, the optimizer's steps and a normalizer. So this server runs it the way Gym runs its
other black-box harnesses: unchanged, on a staged copy of the repository, as `security-agent synthetic bench run`
does, with every model call sent to Gym's model server under this rollout's address.

The scan runs in this server's process, not in the OpenShell sandbox: the code the optimizer wrote for the looped
agent runs here too (`security_agent.synthetic.codecheck` refuses file, process and network imports in it).

The response carries the scan's conversation as output items, and the scan's findings in `metadata.findings`, which
the resources server scores.
"""

import asyncio
import json
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from fastapi import Request
from nemo_gym.base_resources_server import AggregateMetrics, AggregateMetricsRequest, BaseRunRequest, BaseVerifyResponse
from nemo_gym.base_responses_api_agent import BaseResponsesAPIAgentConfig, Body, SimpleResponsesAPIAgent
from nemo_gym.config_types import ModelServerRef, ResourcesServerRef
from nemo_gym.openai_utils import NeMoGymResponse, NeMoGymResponseCreateParamsNonStreaming
from nemo_gym.server_utils import get_response_json, raise_for_status
from pydantic import ConfigDict, PrivateAttr

from security_agent.synthetic.agent import make_scanner
from security_agent.synthetic.bench.adapters import load_benchmark
from security_agent.synthetic.config import REPO_ROOT
from security_agent.synthetic.gym import response_items, scan, scanner_model

EMPTY_MESSAGE = {
    "type": "message",
    "id": "msg_empty",
    "role": "assistant",
    "status": "completed",
    "content": [{"type": "output_text", "text": "", "annotations": []}],
}


class SyntheticAgentConfig(BaseResponsesAPIAgentConfig):
    resources_server: ResourcesServerRef
    model_server: ModelServerRef
    # The candidate directory (pipeline.yaml, prompts/, tools/), absolute or relative to the repository.
    agent: str
    # The scanner's model settings: a file in security_agent/synthetic/config/, or a path. Its server address and
    # model name are replaced by Gym's model server.
    model_settings: str = "model.yaml"
    benchmark: str = "hvbench"
    # Repositories scanned at once by this server.
    concurrency: int = 4


class SyntheticRunRequest(BaseRunRequest):
    model_config = ConfigDict(extra="allow")

    instance_id: str
    pair_id: str


class SyntheticAgentVerifyResponse(BaseVerifyResponse):
    model_config = ConfigDict(extra="allow")


class SyntheticAgent(SimpleResponsesAPIAgent):
    ray_enabled = False
    config: SyntheticAgentConfig

    _candidate: Any = PrivateAttr(default=None)
    _instances: Any = PrivateAttr(default=None)
    _slots: Any = PrivateAttr(default=None)

    def model_post_init(self, context):  # noqa: ANN001, ANN201 - the base class's signature
        """Check the candidate once, and find the benchmark's repositories."""
        candidate = Path(self.config.agent)
        self._candidate = candidate if candidate.is_absolute() else REPO_ROOT / candidate
        make_scanner(self._candidate, {"model": "check", "api_base_url": "http://127.0.0.1"})  # raises if invalid
        benchmark = load_benchmark(self.config.benchmark)
        benchmark.prepare()
        self._instances = {instance.instance_id: instance.path for instance in benchmark.instances()}
        self._slots = asyncio.Semaphore(max(1, self.config.concurrency))
        return super().model_post_init(context)

    async def responses(
        self, request: Request, body: NeMoGymResponseCreateParamsNonStreaming = Body()
    ) -> NeMoGymResponse:
        """Scan the repository named in `metadata.instance_id`."""
        instance_id = (body.metadata or {}).get("instance_id")
        if instance_id not in (self._instances or {}):
            raise ValueError(f"metadata.instance_id names no repository of the benchmark: {instance_id!r}")
        path_params = getattr(request, "path_params", None)
        rollout_id = path_params.get("rollout_id") if isinstance(path_params, Mapping) else None
        model = scanner_model(
            self.config.model_settings, self.resolve_model_base_url(self.config.model_server.name, rollout_id)
        )
        scanner = make_scanner(self._candidate, model)
        async with self._slots:
            report, record, findings = await asyncio.to_thread(scan, scanner, instance_id, self._instances[instance_id])
        trajectory = ((record or {}).get("agent") or {}).get("trajectory") or []
        output = response_items(trajectory) or [EMPTY_MESSAGE]
        prompt, completion = report.cost.prompt_tokens, report.cost.completion_tokens
        return NeMoGymResponse.model_validate(
            {
                "id": f"resp_{uuid.uuid4().hex}",
                "created_at": int(time.time()),
                "model": str(model.get("model", "")),
                "object": "response",
                "output": output,
                "parallel_tool_calls": False,
                "tool_choice": "auto",
                "tools": [],
                "metadata": {
                    "instance_id": instance_id,
                    "findings": json.dumps(findings),
                    "complete": "true" if report.status == "complete" else "false",
                    "error": report.error or "",
                },
                "usage": {
                    "input_tokens": prompt,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens": completion,
                    "output_tokens_details": {"reasoning_tokens": 0},
                    "total_tokens": prompt + completion,
                },
            }
        )

    async def run(self, request: Request, body: SyntheticRunRequest) -> SyntheticAgentVerifyResponse:
        """Seed the resources server's session, scan, and have the scan verified."""
        cookies = request.cookies
        seeded = await self.server_client.post(
            server_name=self.config.resources_server.name,
            url_path="/seed_session",
            json=body.model_dump(),
            cookies=cookies,
        )
        await raise_for_status(seeded)
        cookies = seeded.cookies

        params = body.responses_create_params
        params = params.model_copy(update={"metadata": {**(params.metadata or {}), "instance_id": body.instance_id}})
        scanned = await self.server_client.post(
            server_name=self.config.name,
            url_path=self.url_path_for_run("/v1/responses", body),
            json=params,
            cookies=cookies,
        )
        await raise_for_status(scanned)
        cookies = scanned.cookies

        verified = await self.server_client.post(
            server_name=self.config.resources_server.name,
            url_path="/verify",
            json=body.model_dump() | {"response": await get_response_json(scanned)},
            cookies=cookies,
        )
        await raise_for_status(verified)
        return SyntheticAgentVerifyResponse.model_validate(await get_response_json(verified))

    async def aggregate_metrics(self, body: AggregateMetricsRequest = Body()) -> AggregateMetrics:
        """The resources server's aggregation: the paired metrics are computed there."""
        response = await self.server_client.post(
            server_name=self.config.resources_server.name, url_path="/aggregate_metrics", json=body
        )
        await raise_for_status(response)
        return AggregateMetrics.model_validate(await get_response_json(response))


if __name__ == "__main__":
    SyntheticAgent.run_webserver()
