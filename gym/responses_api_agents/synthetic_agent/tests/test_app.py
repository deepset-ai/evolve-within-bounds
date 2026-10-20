# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""The agent server loads both agents, and turns a scan into Gym's response (the scan itself is stubbed)."""

import json
from unittest.mock import MagicMock

import pytest
from nemo_gym.config_types import ModelServerRef, ResourcesServerRef
from nemo_gym.openai_utils import NeMoGymResponseCreateParamsNonStreaming
from nemo_gym.server_utils import ServerClient
from responses_api_agents.synthetic_agent import app
from responses_api_agents.synthetic_agent.app import SyntheticAgent, SyntheticAgentConfig

from security_agent.synthetic.schema import Cost, Finding, ScanReport

INSTANCE = "instance-e8dcc82c90fcc787432d"  # pair-synth22-01's vulnerable repository
TRAJECTORY = [
    {"role": "user", "text": "Review this repository."},
    {
        "role": "assistant",
        "reasoning": "The footnote builder looks risky.",
        "calls": [{"tool": "read_file", "args": '{"path": "a.py"}'}],
    },
    {"role": "tool", "results": [{"tool": "read_file", "error": None, "result": "1 | x = 1"}]},
    {"role": "assistant", "text": "Done: one finding."},
]
FINDING = {
    "path": "src/custom_components/citation_footnoter/citation_footnoter.py",
    "line_start": 48,
    "line_end": 49,
    "cwe": "CWE-79",
    "title": "Unescaped title",
}


def _agent(name: str) -> SyntheticAgent:
    config = SyntheticAgentConfig(
        host="0.0.0.0",
        port=8080,
        entrypoint="",
        name=f"synthetic_{name}",
        resources_server=ResourcesServerRef(type="resources_servers", name="synthetic"),
        model_server=ModelServerRef(type="responses_api_models", name="synthetic_model"),
        agent=f"agents/synthetic/{name}",
    )
    return SyntheticAgent(config=config, server_client=MagicMock(spec=ServerClient))


@pytest.mark.parametrize("name", ["seed", "looped"])
def test_both_agents_load_and_the_benchmark_is_found(name: str) -> None:
    agent = _agent(name)
    assert agent._candidate.name == name and (agent._candidate / "pipeline.yaml").is_file()
    assert INSTANCE in agent._instances


@pytest.mark.asyncio
async def test_a_scan_becomes_a_response_with_its_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    agent = _agent("seed")
    seen = {}

    def fake_scan(scanner, instance_id, _path):  # noqa: ANN001, ANN202
        seen.update(model=scanner.model, instance_id=instance_id)
        report = ScanReport(
            instance_id=instance_id,
            status="complete",
            verdict="vulnerable",
            findings=[Finding(**FINDING)],
            cost=Cost(prompt_tokens=100, completion_tokens=20),
            scanner="agent",
        )
        return report, {"agent": {"trajectory": TRAJECTORY}}, [FINDING]

    monkeypatch.setattr(app, "scan", fake_scan)
    monkeypatch.setattr(SyntheticAgent, "resolve_model_base_url", lambda *_args, **_kwargs: "http://gym/v1")
    body = NeMoGymResponseCreateParamsNonStreaming(input="Review it.", metadata={"instance_id": INSTANCE})
    response = await agent.responses(MagicMock(path_params={}), body)
    assert seen["instance_id"] == INSTANCE
    assert seen["model"]["api_base_url"] == "http://gym/v1" and seen["model"]["gym_model_server"]
    assert json.loads(response.metadata["findings"]) == [FINDING] and response.metadata["complete"] == "true"
    assert [item.type for item in response.output] == ["reasoning", "function_call", "function_call_output", "message"]
    assert response.usage.total_tokens == 120

    with pytest.raises(ValueError, match="names no repository"):
        await agent.responses(MagicMock(path_params={}), NeMoGymResponseCreateParamsNonStreaming(input="x"))
