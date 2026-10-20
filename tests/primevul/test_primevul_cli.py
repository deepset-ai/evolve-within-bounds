# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

import pytest
from pv_helpers import write_benchmark
from test_measure import FakeAgent

from security_agent import cli
from security_agent.primevul import agent as agents

SEED = Path(__file__).resolve().parents[2] / "agents" / "primevul" / "seed"


def test_run_writes_the_summary_and_one_label_per_pair(tmp_path, monkeypatch, capsys):
    data = write_benchmark(tmp_path / "b.jsonl", pairs_per_split=3)
    seen = []

    def load(config):
        seen.append(config)
        return FakeAgent()

    monkeypatch.setattr(agents, "load_agent", load)
    run_dir = tmp_path / "run"
    with pytest.raises(SystemExit) as exit_code:
        cli.main(
            [
                "primevul",
                "run",
                "--agent",
                str(SEED),
                "--data",
                str(data),
                "--split",
                "test",
                "--pairs",
                "1",
                "--concurrency",
                "1",
                "--run-dir",
                str(run_dir),
            ]
        )
    assert exit_code.value.code == 0
    summary = json.loads((run_dir / "summary.json").read_text())
    assert summary["configuration_id"] == "72e9b7406799d996"
    assert summary["thinking_budget"] == 2048
    assert summary["metrics"]["n_pairs"] == 1
    assert "pairs" not in summary["metrics"]
    assert [json.loads(line) for line in (run_dir / "pairs.jsonl").read_text().splitlines()] == [
        {"pair_id": "holdout-0", "label": "parse_error"}
    ]
    budget = seen[0]["init_parameters"]["chat_generator"]["init_parameters"]["generation_kwargs"]["extra_body"]
    assert budget == {"thinking_token_budget": 2048}
    out = capsys.readouterr().out
    assert "test: 1 pairs, 2 functions" in out
    assert "seed: paired 0.000 (0/1)" in out


def test_a_missing_benchmark_file_is_a_message(tmp_path, capsys):
    with pytest.raises(SystemExit) as exit_code:
        cli.main(["primevul", "run", "--agent", str(SEED), "--data", str(tmp_path / "none.jsonl")])
    assert exit_code.value.code == 2
    assert "hatch run primevul:build" in capsys.readouterr().err
