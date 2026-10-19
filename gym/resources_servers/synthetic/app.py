# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The synthetic benchmark as a NeMo Gym resources server: one repository scanned, its findings scored per pair.

The agent server scans the repository and sends the scan's findings with its response (`metadata.findings`). This
server scores them with the benchmark's own scorer and its answer key (`security_agent.synthetic.gym.Scorer`), which
never leave it. There are no environment tools: the scanner brings its own.

- `verify`: one repository; reward 1.0 when the vulnerable repository has a finding on the planted lines, or the fixed
  twin has none on the same lines.
- `compute_metrics`, `compute_repeat_metrics`: paired localization accuracy and the rest, over the pairs whose two
  repositories were scanned in a repeat, as `security-agent synthetic bench run` reports them; the run's value is
  their mean over the repeats.
"""

import asyncio
import json
from typing import Any

from nemo_gym.base_resources_server import (
    BaseResourcesServerConfig,
    BaseRunRequest,
    BaseVerifyRequest,
    BaseVerifyResponse,
    SimpleResourcesServer,
)
from pydantic import ConfigDict, PrivateAttr

from security_agent.synthetic.gym import Scorer

KEY_METRICS = (
    "paired_localization_accuracy",
    "baseline_mapped_localization_false_alarm_rate",
    "mutant_localization_recall",
)


class SyntheticResourcesServerConfig(BaseResourcesServerConfig):
    name: str = "synthetic"
    # The benchmark, as in security_agent/synthetic/config/benchmarks.yaml.
    benchmark: str = "hvbench"


class SyntheticRunRequest(BaseRunRequest):
    model_config = ConfigDict(extra="allow")

    instance_id: str
    pair_id: str


class SyntheticVerifyRequest(SyntheticRunRequest, BaseVerifyRequest):
    pass


class SyntheticVerifyResponse(BaseVerifyResponse):
    model_config = ConfigDict(extra="allow")

    right: bool
    member: str
    findings: list[dict[str, Any]]
    complete: bool


class SyntheticResourcesServer(SimpleResourcesServer):
    ray_enabled = False
    config: SyntheticResourcesServerConfig

    _scorer: Any = PrivateAttr(default=None)

    def scorer(self) -> Scorer:
        """The benchmark's scorer, loaded once."""
        if self._scorer is None:
            self._scorer = Scorer(self.config.benchmark)
        return self._scorer

    async def verify(self, body: SyntheticVerifyRequest) -> SyntheticVerifyResponse:
        """Score one repository's findings."""
        metadata = body.response.metadata or {}
        findings = json.loads(metadata.get("findings") or "[]")
        scored = await asyncio.to_thread(self.scorer().reward, body.instance_id, findings)
        return SyntheticVerifyResponse(
            **body.model_dump(), **scored, findings=findings, complete=metadata.get("complete") == "true"
        )

    def compute_metrics(self, tasks: list[list[dict[str, Any]]]) -> dict[str, Any]:
        """The paired metrics over the whole run: each repeat's, averaged."""
        return self.scorer().mean_over_repeats([row for rollouts in tasks for row in rollouts])

    def compute_repeat_metrics(self, tasks: list[list[dict[str, Any]]]) -> dict[str, Any]:
        """The paired metrics over the pairs of one repeat."""
        return self.scorer().pair_metrics([row for rollouts in tasks for row in rollouts])

    def get_key_metrics(self, agent_metrics: dict[str, Any]) -> dict[str, Any]:
        """Paired localization accuracy first: it is the benchmark's number; the mean reward is per repository."""
        return {
            key: value
            for key, value in agent_metrics.items()
            if any(key.endswith(name) for name in KEY_METRICS) or key == "mean/reward"
        }


if __name__ == "__main__":
    SyntheticResourcesServer.run_webserver()
