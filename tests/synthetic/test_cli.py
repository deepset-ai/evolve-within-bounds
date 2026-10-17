# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json

import pytest
import yaml
from fake_vllm import FakeVllm
from helpers import SEED, PairBenchmark, model

import security_agent.synthetic.cli as synthetic_cli
import security_agent.synthetic.config as config_module
from security_agent import cli


@pytest.mark.parametrize("pair, accuracy", [("pair-a", 1.0), ("pair-b", 0.0)])
def test_bench_run_scores_only_the_selected_pairs(tmp_path, monkeypatch, pair, accuracy):
    bench = PairBenchmark(tmp_path)
    monkeypatch.setattr(synthetic_cli, "load_benchmark", lambda name: bench)
    with FakeVllm() as server:
        (tmp_path / "config").mkdir()
        (tmp_path / "config" / "model.yaml").write_text(yaml.safe_dump(model(server.base_url)))
        monkeypatch.setattr(config_module, "CONFIG_DIR", tmp_path / "config")
        with pytest.raises(SystemExit) as exit_code:
            cli.main(
                [
                    "synthetic",
                    "bench",
                    "run",
                    "--candidate",
                    str(SEED),
                    "--pair",
                    pair,
                    "--run-dir",
                    str(tmp_path / "run"),
                ]
            )
    assert exit_code.value.code == 0
    summary = json.loads((tmp_path / "run" / "summary.json").read_text())
    assert summary["pairs"] == 1 and summary["paired_localization_accuracy"] == accuracy
    assert json.loads((tmp_path / "run" / "manifest.json").read_text())["subset"]


def test_the_parser_knows_the_commands():
    parser = cli.build_parser()
    args = parser.parse_args(["synthetic", "bench", "run", "--candidate", "x", "--split", "test", "--sandbox", "s"])
    assert (args.split, args.sandbox, args.benchmark, args.model_config) == ("test", "s", "hvbench", "model.yaml")
    assert parser.parse_args(["synthetic", "loop", "run", "--smoke"]).config == "loop.yaml"
    with pytest.raises(SystemExit):
        parser.parse_args(["synthetic", "bench", "run", "--candidate", "x", "--split", "val", "--pair", "p"])


def test_config_names_and_paths(tmp_path):
    (tmp_path / "mine.yaml").write_text("a: 1\n")
    assert config_module.load_yaml("loop.yaml")["iterations"] == 15  # a file in the package's config/
    assert config_module.load_yaml(tmp_path / "mine.yaml") == {"a": 1}  # any other path
