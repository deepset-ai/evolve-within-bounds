# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The PrimeVul agents as a NeMo Gym agent server: Gym's Haystack harness, given one of our agent files.

At start the agent file (`agent:` in the config, e.g. agents/primevul/seed) becomes the harness's pipeline
(`security_agent.primevul.gym.harness_pipeline`): the same prompt, tool and budgets, with Gym's chat generator in place
of the OpenAI one. The knowledge-base tool runs in this process, as in our runner, and reaches the model server and
Qdrant directly.
"""

import os
import tempfile
from pathlib import Path

import yaml
from responses_api_agents.haystack_agent.app import HaystackAgent, HaystackAgentConfig

from security_agent.primevul.agent import load_config
from security_agent.primevul.gym import harness_pipeline
from security_agent.primevul.tasks import REPO_ROOT

# The knowledge-base sub-agent reads its API key from OPENAI_API_KEY; the local model server does not check it.
os.environ.setdefault("OPENAI_API_KEY", "EMPTY")


class PrimeVulAgentConfig(HaystackAgentConfig):
    # The agent's directory (with agent.yaml), absolute or relative to the repository.
    agent: str
    # Written at start from `agent`.
    pipeline_yaml: str = ""


class PrimeVulAgent(HaystackAgent):
    config: PrimeVulAgentConfig

    def model_post_init(self, context):  # noqa: ANN001, ANN201 - the harness's signature
        """Write the agent file as the harness's pipeline, then start the harness on it."""
        agent_dir = Path(self.config.agent)
        if not agent_dir.is_absolute():
            agent_dir = REPO_ROOT / agent_dir
        pipeline = Path(tempfile.mkdtemp(prefix="primevul-agent-")) / "pipeline.yaml"
        pipeline.write_text(yaml.safe_dump(harness_pipeline(load_config(agent_dir)), sort_keys=False), encoding="utf-8")
        self.config.pipeline_yaml = str(pipeline)
        return super().model_post_init(context)


if __name__ == "__main__":
    PrimeVulAgent.run_webserver()
