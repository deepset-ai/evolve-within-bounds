# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""The agent files are the agents that produced the results, by configuration id."""

import copy
from pathlib import Path

import pytest

from security_agent.primevul.agent import configuration_id, load_agent, load_config, with_thinking_budget

AGENTS = Path(__file__).resolve().parents[2] / "agents" / "primevul"
IDS = {"seed": "72e9b7406799d996", "looped": "2fb8795618a22434"}


@pytest.mark.parametrize("name", sorted(IDS))
def test_configuration_ids(name):
    assert configuration_id(load_config(AGENTS / name)) == IDS[name]


def test_the_loop_changed_only_the_system_prompt_and_the_tool_description():
    seed, looped = (load_config(AGENTS / name) for name in ("seed", "looped"))
    assert seed["init_parameters"]["system_prompt"] != looped["init_parameters"]["system_prompt"]
    for config in (seed, looped):
        config["init_parameters"]["system_prompt"] = ""
        config["init_parameters"]["tools"][0]["data"]["description"] = ""
    assert seed == looped


def test_thinking_budget_is_added_per_request_without_touching_the_file():
    config = load_config(AGENTS / "seed")
    original = copy.deepcopy(config)
    budgeted = with_thinking_budget(config, 2048)
    kwargs = budgeted["init_parameters"]["chat_generator"]["init_parameters"]["generation_kwargs"]
    assert kwargs == {"max_tokens": 8000, "temperature": 0.0, "extra_body": {"thinking_token_budget": 2048}}
    assert config == original
    assert with_thinking_budget(config, None) == original


@pytest.mark.parametrize("name", sorted(IDS))
def test_agents_deserialize_without_loading_models(name):
    pytest.importorskip("haystack_integrations.agent_pack")
    agent = load_agent(load_config(AGENTS / name))
    assert [tool.name for tool in agent.tools] == ["search_security_kb"]
    assert agent.chat_generator.model == "qwen3.8-flash-next"
