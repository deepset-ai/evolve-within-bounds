# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The synthetic custom-component benchmark as a task for the shared loop (`security_agent.optimize`).

- **Candidates** are repository scanners (`security_agent.synthetic.agent`): a Haystack pipeline around an Agent, with
  the tools and steps the optimizer writes in Python.
- **Measuring** scans both repositories of every pair (inside the OpenShell sandbox, when there is one) and scores them
  with the benchmark's own scorer (`security_agent.synthetic.measure`).
- **The optimizer's tools** try a code file or the whole draft on a training pair (`run_tool`, `trial_scan`, in the
  sandbox too) and show what the agent did on one (`read_reasoning`).
- **The prompt** is `prompts/optimizer.md`, with the contract and the experiment's numbers filled in.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from string import Template
from typing import Any

from security_agent.optimize.measurement import Measurement
from security_agent.optimize.splits import load_split
from security_agent.synthetic import measure as measuring
from security_agent.synthetic.agent import check_candidate, contract_test, describe_contract
from security_agent.synthetic.bench.adapters import load_benchmark
from security_agent.synthetic.bench.pairs import load_pairs, pair_targets
from security_agent.synthetic.config import CONFIG_DIR, PROMPTS_DIR, load_yaml
from security_agent.synthetic.digest import render, shown_material
from security_agent.synthetic.examples import EXAMPLE_CALLS, Examples
from security_agent.synthetic.traces import MAX_READS, ReasoningReader

SPLIT = CONFIG_DIR / "split.json"
EXAMPLE_KEY = {"type": "string", "description": "A training pair key from the digests, e.g. 'hvbench/pair-...-01'."}
TOOL_SPECS: dict[str, dict[str, Any]] = {
    "run_tool": {
        "description": (
            "Debug one code file of the draft on a training pair. A tool (KIND tool) runs once with `arguments` on the "
            "vulnerable repository: you see its output (as the agent would), errors, time and any findings it "
            "reported. A step (KIND step) runs on both repositories with the agent's findings from the draft's latest "
            f"run as input: you see what it dropped, changed or added. Model calls are real (at most {EXAMPLE_CALLS})."
        ),
        "parameters": {
            "path": {"type": "string", "description": "tools/<name>.py"},
            "example": EXAMPLE_KEY,
            "arguments": {"type": "object", "description": "For a tool: its arguments, as the agent would pass them."},
        },
        "required": ["path", "example"],
    },
    "trial_scan": {
        "description": (
            "Scan one training pair (both repositories) with the whole draft, exactly as a measurement would, with "
            "real model calls: whether the pair comes out right, the findings near the planted lines, why the agent "
            "stopped, its steps and tool calls, errors, and the estimated GPU minutes. The draft must be valid. It "
            "takes minutes; at most 3 per turn. Use it before you submit a larger change."
        ),
        "parameters": {"example": EXAMPLE_KEY},
        "required": ["example"],
    },
    "read_reasoning": {
        "description": (
            "Read what the agent did on one training pair in the draft's latest measurement: step by step, its "
            "reasoning, tool calls and their results (shortened; steps that mention the planted file get more room), "
            "why it stopped, and what it reported in the planted file. Use it on the digests' pairs to find out why a "
            f"defect was missed, cited at the wrong lines, or reported on the safe twin. At most {MAX_READS} reads per "
            "turn; costs no GPU."
        ),
        "parameters": {
            "example": EXAMPLE_KEY,
            "side": {
                "type": "string",
                "enum": ["vulnerable", "safe_twin"],
                "description": "Which repository of the pair (default vulnerable).",
            },
            "run": {"type": "integer", "description": "Which of the draft's runs, starting at 1 (default 1)."},
        },
        "required": ["example"],
    },
}


def split() -> dict[str, dict[str, list[str]]]:
    """The benchmark's split: 25 training, 13 validation and 12 test pairs, by repository."""
    return load_split(SPLIT)


class SyntheticTask:
    """
    The synthetic benchmark, as the loop sees it.

    :param model_config: the model server's settings, a file in `config/` or a dict.
    :param concurrency: repositories scanned in parallel.
    :param sandbox: a `security_agent.synthetic.sandbox.OpenShell`; scans and the optimizer's code then run in it.
    :param prefill_tps: prompt tokens per second, for GPU-time estimates.
    :param decode_tps: output tokens per second, likewise.
    """

    name = "synthetic"
    unit = "repository"

    def __init__(
        self,
        *,
        model_config: str | dict = "model.yaml",
        concurrency: int = 8,
        sandbox: Any = None,
        prefill_tps: float = 3000.0,
        decode_tps: float = 110.0,
        bench_loader: Callable[[str], Any] = load_benchmark,
        log: Callable[[str], None] = print,
    ) -> None:
        self.model = dict(model_config) if isinstance(model_config, dict) else load_yaml(model_config)
        self.concurrency = concurrency
        self.sandbox = sandbox
        self.prefill_tps, self.decode_tps = prefill_tps, decode_tps
        self.bench_loader = bench_loader
        self.log = log

    def measure(
        self,
        candidate: Path,
        parts: list[dict[str, list[str]]],
        out_dir: Path,
        *,
        label: str,
        abort: Callable[[Measurement], bool] | None = None,
    ) -> Measurement:
        """Scan both repositories of every pair and score them; `abort` is checked between parts."""
        return measuring.measure(
            candidate,
            parts,
            out_dir,
            label=label,
            abort=abort,
            model_config=self.model,
            concurrency=self.concurrency,
            log=self.log,
            bench_loader=self.bench_loader,
            sandbox=self.sandbox,
        )

    def render(self, digest: dict[str, Any]) -> str:
        """One failure digest as text."""
        return render(digest)

    def shown_material(self, digests: list[dict[str, Any]]) -> dict[str, list[str]]:
        """Paths, repositories, titles and code lines the digests show."""
        return shown_material(digests)

    def training_material(self, train: dict[str, list[str]]) -> dict[str, list[str]]:
        """Every training pair's planted paths, repository and title."""
        shown: dict[str, list[str]] = {"paths": [], "repositories": [], "titles": []}
        for name, pair_ids in train.items():
            rows = load_pairs(self.bench_loader(name))
            for row in (rows[p] for p in pair_ids):
                shown["paths"] += [t["path"] for t in pair_targets(row)]
                shown["repositories"].append(row.get("repository", ""))
                if row.get("title"):
                    shown["titles"].append(row["title"])
        return shown

    def scoring(self) -> str:
        """How a pair is scored."""
        return (
            "A pair is right when the scanner reports a finding within 2 lines of the planted lines in the "
            "vulnerable repository, whatever its CWE, and none within 2 lines of the corresponding lines of the "
            "safe twin."
        )

    def workspace_options(
        self,
        train: dict[str, list[str]],
        best: Callable[[], Measurement | None],
        on_shown: Callable[[dict[str, list[str]]], None],
    ) -> dict[str, Any]:
        """The contract, the contract test (in the sandbox, when there is one), and the optimizer's three tools."""

        def record(benchmark: str, instance_id: str) -> dict | None:
            return measuring.record(best(), benchmark, instance_id)

        examples = Examples(
            train,
            record,
            model=self.model,
            bench_loader=self.bench_loader,
            prefill_tps=self.prefill_tps,
            decode_tps=self.decode_tps,
            sandbox=self.sandbox,
        )
        return {
            "check": check_candidate,
            "contract_check": self.sandbox.contract_test if self.sandbox is not None else contract_test,
            "example_runner": examples,
            "trial_runner": examples.trial,
            "reasoning_reader": ReasoningReader(train, record, on_shown=on_shown, bench_loader=self.bench_loader),
            "tool_specs": TOOL_SPECS,
            "max_reasoning_reads": MAX_READS,
        }

    def spoiled(self, measurement: Measurement) -> int:
        """Drop scans a model-server outage spoiled; how many will run again."""
        return measuring.spoiled(measurement)

    def system_prompt(self, values: dict[str, Any]) -> str:
        """The optimizer's system prompt with the contract and the experiment's numbers filled in."""
        template = Template((PROMPTS_DIR / "optimizer.md").read_text(encoding="utf-8"))
        return template.substitute(limits=describe_contract(), **values)

    @staticmethod
    def prompt_values(config: dict[str, Any], train: dict[str, list[str]]) -> dict[str, Any]:
        """The experiment's numbers in the prompt."""
        rules = config["rules"]
        train_pairs = sum(len(ids) for ids in train.values())
        return {
            "train_pairs": train_pairs,
            "train_repos": 2 * train_pairs,
            # GPU-hours that 1,000 output tokens per training repository cost, for budgeting the code's model calls
            "call_hours": round(2 * train_pairs * 1000 / float(rules["decode_tps"]) / 3600, 2),
            "budget_hours": config["gpu_hours"],
            "abort_behind": rules["abort_behind"],
            "max_gpu_minutes_per_repo": rules["max_gpu_minutes_per_repo"],
            "max_findings_per_repo": rules["max_findings_per_repo"],
        }
