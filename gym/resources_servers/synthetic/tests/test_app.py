# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""The resources server against Gym's own request and response models, with the benchmark's own scorer."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from nemo_gym.openai_utils import NeMoGymResponse, NeMoGymResponseOutputMessage, NeMoGymResponseOutputText
from nemo_gym.server_utils import ServerClient
from resources_servers.synthetic.app import (
    SyntheticResourcesServer,
    SyntheticResourcesServerConfig,
    SyntheticVerifyRequest,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "data" / "example.jsonl"
# pair-synth22-01's planted lines: the citation's title and URL, embedded without escaping.
PLANTED = {
    "path": "src/custom_components/citation_footnoter/citation_footnoter.py",
    "line_start": 48,
    "line_end": 49,
    "cwe": "CWE-79",
    "title": "Citation title and URL embedded without escaping",
}


def _response(findings: list[dict]) -> NeMoGymResponse:
    return NeMoGymResponse(
        id="test",
        created_at=0.0,
        model="test_model",
        object="response",
        output=[
            NeMoGymResponseOutputMessage(
                id="msg",
                content=[NeMoGymResponseOutputText(annotations=[], text="Done.", type="output_text")],
                role="assistant",
                status="completed",
                type="message",
            )
        ],
        parallel_tool_calls=False,
        tool_choice="none",
        tools=[],
        metadata={"findings": json.dumps(findings), "complete": "true"},
    )


def _server() -> SyntheticResourcesServer:
    config = SyntheticResourcesServerConfig(host="0.0.0.0", port=8080, entrypoint="", name="")
    return SyntheticResourcesServer(config=config, server_client=MagicMock(spec=ServerClient))


def _rows() -> dict[tuple[str, int], dict]:
    """(pair_id, position in the pair) -> row: 0 is the vulnerable repository, 1 its fixed twin."""
    rows = [json.loads(line) for line in EXAMPLE.read_text().splitlines()]
    seen: dict[str, int] = {}
    out = {}
    for row in rows:
        position = seen.get(row["pair_id"], 0)
        seen[row["pair_id"]] = position + 1
        out[(row["pair_id"], position)] = row
    return out


@pytest.mark.asyncio
async def test_verify_rewards_the_planted_lines_and_a_quiet_fixed_twin() -> None:
    server, rows = _server(), _rows()
    vulnerable, fixed = rows[("pair-synth22-01", 0)], rows[("pair-synth22-01", 1)]
    found = await server.verify(SyntheticVerifyRequest(**vulnerable, response=_response([PLANTED])))
    assert found.reward == pytest.approx(1.0) and found.member == "mutant" and found.complete
    missed = await server.verify(SyntheticVerifyRequest(**vulnerable, response=_response([])))
    assert missed.reward == pytest.approx(0.0)
    quiet = await server.verify(SyntheticVerifyRequest(**fixed, response=_response([])))
    assert quiet.reward == pytest.approx(1.0) and quiet.member == "baseline"
    flagged = await server.verify(SyntheticVerifyRequest(**fixed, response=_response([PLANTED])))
    assert flagged.reward == pytest.approx(0.0)


@pytest.mark.asyncio
async def test_a_pair_is_right_only_when_both_repositories_are() -> None:
    server, rows = _server(), _rows()
    answers = {
        ("pair-synth22-01", 0): [PLANTED],
        ("pair-synth22-01", 1): [],
        ("pair-synth01-01", 0): [],  # missed
        ("pair-synth01-01", 1): [],
    }
    tasks = []
    for key, findings in answers.items():
        verified = await server.verify(SyntheticVerifyRequest(**rows[key], response=_response(findings)))
        tasks.append([verified.model_dump()])
    metrics = server.compute_repeat_metrics(tasks)
    assert metrics["pairs"] == 2
    assert metrics["paired_localization_accuracy"] == pytest.approx(0.5)
    assert metrics["baseline_mapped_localization_false_alarm_rate"] == pytest.approx(0.0)
    assert server.compute_metrics(tasks)["paired_localization_accuracy"] == pytest.approx(0.5)
