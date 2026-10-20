# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""The resources server against Gym's own request and response models (`hatch run gym:gym env test ...`)."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from nemo_gym.openai_utils import NeMoGymResponse, NeMoGymResponseOutputMessage, NeMoGymResponseOutputText
from nemo_gym.server_utils import ServerClient
from resources_servers.primevul.app import PrimeVulResourcesServer, PrimeVulResourcesServerConfig, PrimeVulVerifyRequest

EXAMPLE = Path(__file__).resolve().parents[1] / "data" / "example.jsonl"
VERDICT = {"is_vulnerable": True, "cwe": "CWE-787", "vulnerable_lines": [3], "rationale": "unbounded copy"}


def _response(text: str) -> NeMoGymResponse:
    return NeMoGymResponse(
        id="test",
        created_at=0.0,
        model="test_model",
        object="response",
        output=[
            NeMoGymResponseOutputMessage(
                id="msg",
                content=[NeMoGymResponseOutputText(annotations=[], text=text, type="output_text")],
                role="assistant",
                status="completed",
                type="message",
            )
        ],
        parallel_tool_calls=False,
        tool_choice="none",
        tools=[],
    )


def _server() -> PrimeVulResourcesServer:
    config = PrimeVulResourcesServerConfig(host="0.0.0.0", port=8080, entrypoint="", name="")
    return PrimeVulResourcesServer(config=config, server_client=MagicMock(spec=ServerClient))


def _rows() -> list[dict]:
    return [json.loads(line) for line in EXAMPLE.read_text().splitlines()]


@pytest.mark.asyncio
async def test_verify_scores_the_final_verdict() -> None:
    server, row = _server(), _rows()[0]
    right = await server.verify(PrimeVulVerifyRequest(**row, response=_response(json.dumps(VERDICT))))
    assert right.reward == pytest.approx(1.0) and right.correct and right.cwe_correct
    wrong = await server.verify(PrimeVulVerifyRequest(**row, response=_response("I am not sure.")))
    assert wrong.reward == pytest.approx(0.0) and wrong.parse_error


@pytest.mark.asyncio
async def test_paired_accuracy_counts_a_pair_only_when_both_verdicts_are_right() -> None:
    server = _server()
    benign = {"is_vulnerable": False, "cwe": None, "vulnerable_lines": [], "rationale": "checked"}
    answers = [VERDICT, benign, VERDICT, VERDICT]  # pair 0 right; pair 1's patched twin called vulnerable
    tasks = []
    for row, answer in zip(_rows(), answers, strict=True):
        verified = await server.verify(PrimeVulVerifyRequest(**row, response=_response(json.dumps(answer))))
        tasks.append([verified.model_dump()])
    metrics = server.compute_repeat_metrics(tasks)
    assert metrics["paired_accuracy"] == pytest.approx(0.5)
    assert metrics["pairs_missed_fix"] == 1
    assert metrics["pair_false_positive_rate"] == pytest.approx(0.5)
