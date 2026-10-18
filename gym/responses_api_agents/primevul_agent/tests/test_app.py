# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""Gym's Haystack harness loads both agent files unchanged, but for the chat generator (no model server needed)."""

from unittest.mock import MagicMock

import pytest
from nemo_gym.config_types import ModelServerRef, ResourcesServerRef
from nemo_gym.server_utils import ServerClient
from responses_api_agents.haystack_agent.chat_generator import NeMoGymResponsesChatGenerator
from responses_api_agents.primevul_agent.app import PrimeVulAgent, PrimeVulAgentConfig

from security_agent.primevul.agent import load_config
from security_agent.primevul.tasks import REPO_ROOT


@pytest.mark.parametrize("name", ["seed", "looped"])
def test_the_harness_runs_the_agent_file(name: str) -> None:
    config = PrimeVulAgentConfig(
        host="0.0.0.0",
        port=8080,
        entrypoint="",
        name=f"primevul_{name}",
        resources_server=ResourcesServerRef(type="resources_servers", name="primevul"),
        model_server=ModelServerRef(type="responses_api_models", name="policy_model"),
        agent=f"agents/primevul/{name}",
    )
    agent = PrimeVulAgent(config=config, server_client=MagicMock(spec=ServerClient))
    original = load_config(REPO_ROOT / "agents" / "primevul" / name)["init_parameters"]
    assert isinstance(agent._generator, NeMoGymResponsesChatGenerator)
    assert agent._generator.server_name == "policy_model"
    assert agent._agent.system_prompt == original["system_prompt"]
    assert agent._agent.max_agent_steps == original["max_agent_steps"]
    assert [tool.name for tool in agent._configured_tools] == ["search_security_kb"]
    assert type(agent._configured_tools[0]._component).__name__ == "SecurityKbSearch"
