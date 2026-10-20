# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
PrimeVul as a NeMo Gym resources server: one function in, one JSON verdict out, scored per pair.

There is no per-rollout state and there are no environment tools (the knowledge-base tool runs inside the agent), so
the server only verifies and aggregates. The scoring is `security_agent.primevul.gym`, the same as our runner's.

- `verify`: one rollout; reward 1.0 when the function's verdict is right.
- `compute_metrics`, `compute_repeat_metrics`: paired accuracy and the rest, over the pairs of each repeat; the run's
  value is their mean, as Gym reports it.
"""

from typing import Any

from nemo_gym.base_resources_server import (
    BaseResourcesServerConfig,
    BaseRunRequest,
    BaseVerifyRequest,
    BaseVerifyResponse,
    SimpleResourcesServer,
)
from pydantic import ConfigDict

from security_agent.primevul.gym import mean_over_repeats, pair_metrics, score

KEY_METRICS = ("paired_accuracy", "pair_false_positive_rate", "parse_error_rate", "split_rate", "right_way_rate")


class PrimeVulResourcesServerConfig(BaseResourcesServerConfig):
    name: str = "primevul"


class PrimeVulRunRequest(BaseRunRequest):
    model_config = ConfigDict(extra="allow")

    task_id: str
    pair_id: str
    gold_is_vulnerable: bool
    gold_cwe: str | None = None


class PrimeVulVerifyRequest(PrimeVulRunRequest, BaseVerifyRequest):
    pass


class PrimeVulVerifyResponse(BaseVerifyResponse):
    model_config = ConfigDict(extra="allow")

    correct: bool
    parse_error: bool
    pred_is_vulnerable: bool | None = None
    pred_cwe: str | None = None
    cwe_correct: bool = False


class PrimeVulResourcesServer(SimpleResourcesServer):
    ray_enabled = False
    config: PrimeVulResourcesServerConfig

    async def verify(self, body: PrimeVulVerifyRequest) -> PrimeVulVerifyResponse:
        """Score one rollout."""
        scored = score(body.response.model_dump(), body.model_dump())
        return PrimeVulVerifyResponse(**body.model_dump(), **scored)

    def compute_metrics(self, tasks: list[list[dict[str, Any]]]) -> dict[str, Any]:
        """Paired accuracy and its companions over the whole run: each repeat's, averaged."""
        return mean_over_repeats([row for rollouts in tasks for row in rollouts])

    def compute_repeat_metrics(self, tasks: list[list[dict[str, Any]]]) -> dict[str, Any]:
        """Paired accuracy and its companions over the pairs of one repeat."""
        return pair_metrics([row for rollouts in tasks for row in rollouts])

    def get_key_metrics(self, agent_metrics: dict[str, Any]) -> dict[str, Any]:
        """Paired accuracy first: it is the benchmark's number, the mean reward is per-function accuracy."""
        return {
            key: value
            for key, value in agent_metrics.items()
            if any(key.endswith(name) for name in KEY_METRICS) or key == "mean/reward"
        }


if __name__ == "__main__":
    PrimeVulResourcesServer.run_webserver()
