# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The synthetic benchmark as a NeMo Gym environment: the parts that do not need Gym installed.

The environment is in gym/: a resources server that scores each scan with the benchmark's own scorer, and an agent
server that runs our scanner on the repository a row names. The scanner is a pipeline around a Haystack Agent, with
its own tools, the optimizer's steps and a normalizer, so Gym runs it the way it runs its other black-box harnesses:
unchanged, with every model call sent to Gym's model server.

- `task_rows`, `export`: the vulnerable repository and the fixed twin of each pair of a split, one row each. A row
  names its repository and its pair; the answer key stays with the resources server. Placebo repositories are left
  out: they do not enter the paired metrics.
- `scanner_model`: the scanner's model settings, pointed at Gym's model server.
- `scan`: one repository, as `security-agent synthetic bench run` scans it: staged, scanned, exported.
- `response_items`: the scan's conversation (its record's trajectory) as Responses output items.
- `Scorer`: the benchmark's scorer with its answer key. `reward` scores one repository: 1.0 when the vulnerable one
  has a finding on the planted lines, or the fixed twin has none on the same lines. `pair_metrics` scores the pairs
  whose two repositories were scanned, with the numbers `bench run` reports; `mean_over_repeats` averages them over
  Gym's repeats.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from security_agent.optimize.splits import pairs as split_pairs
from security_agent.synthetic.bench.adapters import Benchmark, load_benchmark
from security_agent.synthetic.bench.pairs import is_planted, load_pairs, summarize_pairs
from security_agent.synthetic.config import load_yaml
from security_agent.synthetic.export import ExportStats, benchmark_record
from security_agent.synthetic.schema import ScanReport
from security_agent.synthetic.staging import stage

BENCHMARK = "hvbench"
REPEAT_KEY = "_ng_rollout_index"  # Gym's repeat number on each verified row
MEMBERS = (("mutant", "mutant_instance_id"), ("baseline", "baseline_instance_id"))
METRIC_KEYS = (
    "paired_localization_accuracy",
    "strict_paired_accuracy",
    "mutant_localization_recall",
    "baseline_mapped_localization_false_alarm_rate",
)


def task_rows(benchmark: Benchmark, pair_ids: list[str]) -> list[dict[str, Any]]:
    """Two rows per planted pair: its vulnerable repository and its fixed twin."""
    pairs = load_pairs(benchmark)
    rows = []
    for pair_id in pair_ids:
        pair = pairs[pair_id]
        if not is_planted(pair):
            continue
        for _, key in MEMBERS:
            instance_id = pair[key]
            text = f"Review the repository {pair.get('repository', instance_id)} for security vulnerabilities."
            rows.append(
                {
                    "responses_create_params": {
                        "input": [{"role": "user", "content": text}],
                        "metadata": {"instance_id": instance_id},
                    },
                    "instance_id": instance_id,
                    "pair_id": pair_id,
                }
            )
    return rows


def export(split: str, out: Path, max_pairs: int | None = None, benchmark_name: str = BENCHMARK) -> int:
    """Write the rows of one split's pairs (the first `max_pairs`, in the split's order) to `out`; returns how many."""
    from security_agent.synthetic.task import split as synthetic_split

    benchmark = load_benchmark(benchmark_name)
    benchmark.prepare()
    pair_ids = split_pairs(split, synthetic_split()).get(benchmark.name, [])[:max_pairs]
    rows = task_rows(benchmark, pair_ids)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    return len(rows)


def scanner_model(model_config: str | dict[str, Any], base_url: str, served_model: str | None = None) -> dict[str, Any]:
    """The scanner's model settings (`config/model.yaml`), with the model calls sent to Gym's model server."""
    model = dict(model_config) if isinstance(model_config, dict) else load_yaml(model_config)
    model.update(api_base_url=base_url, gym_model_server=True)
    if served_model:
        model["model"] = served_model
    return model


def scan(scanner: Any, instance_id: str, path: Path) -> tuple[ScanReport, dict[str, Any] | None, list[dict[str, Any]]]:
    """Scan one repository: its report, its record, and its findings as the benchmark's scorer reads them."""
    staged = stage(path)
    try:
        result = scanner.scan(staged)
    finally:
        staged.cleanup()
    report = ScanReport.from_result(instance_id, scanner.name, result)
    return report, result.record, benchmark_record(report, ExportStats())["findings"]


def response_items(trajectory: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    A scan's conversation as Responses output items, from the record's trajectory.

    The first user message is the request's input and is left out. The record keeps long tool arguments and results
    shortened; Gym's model server keeps the full model calls.
    """
    items: list[dict[str, Any]] = []
    pending: list[str] = []
    for index, step in enumerate(trajectory[1:], 1):
        if step.get("role") == "assistant":
            if step.get("reasoning"):
                summary = [{"type": "summary_text", "text": step["reasoning"]}]
                items.append({"type": "reasoning", "id": f"rs_{index}", "summary": summary})
            if step.get("text"):
                content = [{"type": "output_text", "text": step["text"], "annotations": []}]
                items.append(
                    {
                        "type": "message",
                        "id": f"msg_{index}",
                        "role": "assistant",
                        "status": "completed",
                        "content": content,
                    }
                )
            for n, call in enumerate(step.get("calls") or []):
                call_id = f"call_{index}_{n}"
                pending.append(call_id)
                items.append(
                    {
                        "type": "function_call",
                        "call_id": call_id,
                        "name": call.get("tool", ""),
                        "arguments": call.get("args", ""),
                    }
                )
        for result in step.get("results") or []:
            call_id = pending.pop(0) if pending else f"call_{index}"
            output = f"error: {result['error']}" if result.get("error") else str(result.get("result", ""))
            items.append({"type": "function_call_output", "call_id": call_id, "output": output})
    return items


class Scorer:
    """
    The benchmark's own scorer, with its answer key (written by `security-agent synthetic bench prepare`).

    :param benchmark: the benchmark, or its name as in `config/benchmarks.yaml`.
    """

    def __init__(self, benchmark: str | Benchmark = BENCHMARK) -> None:
        self.benchmark = load_benchmark(benchmark) if isinstance(benchmark, str) else benchmark
        self.benchmark.prepare()
        key = json.loads(self.benchmark.answer_key_path.read_text(encoding="utf-8"))["instances"]
        self.members = {row["instance_id"]: (row["pair_id"], row["member"]) for row in key}

    def score(self, findings: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
        """The scorer's report on these repositories' findings; the other repositories count as not scanned."""
        with tempfile.TemporaryDirectory(prefix="synthetic-gym-") as tmp:
            predictions = Path(tmp) / "predictions.jsonl"
            predictions.write_text(
                "".join(
                    json.dumps({"instance_id": i, "findings": f}, sort_keys=True) + "\n" for i, f in findings.items()
                ),
                encoding="utf-8",
            )
            return self.benchmark.score(predictions, Path(tmp) / "score.json", allow_missing=True)

    def reward(self, instance_id: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """One repository: whether it was scanned right, and which member of its pair it is."""
        if instance_id not in self.members:
            raise ValueError(f"unknown repository {instance_id}")
        pair_id, member = self.members[instance_id]
        if member not in dict(MEMBERS):
            raise ValueError(f"{instance_id} is a {member} repository; the environment has the planted pairs' only")
        row = next(r for r in self.score({instance_id: findings})["pair_results"] if r["pair_id"] == pair_id)
        right = bool(row["mutant_localized"]) if member == "mutant" else not row["baseline_mapped_localization_alarm"]
        return {"reward": float(right), "right": right, "member": member}

    def pair_metrics(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        """The pairs whose two repositories are among `rows` (`instance_id`, `findings`), as `bench run` sums up."""
        findings = {str(row["instance_id"]): list(row.get("findings") or []) for row in rows}
        scanned = {self.members[i][0] for i in findings if i in self.members}
        complete = {
            pair_id
            for pair_id in scanned
            if all(i in findings for i, (p, m) in self.members.items() if p == pair_id and m in dict(MEMBERS))
        }
        if not complete:
            return {}
        summary = summarize_pairs(self.score(findings)["pair_results"], complete)
        return {key: summary[key] for key in ("pairs", *METRIC_KEYS)}

    def mean_over_repeats(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        """`pair_metrics` of each repeat (`REPEAT_KEY`), averaged."""
        by_repeat: dict[Any, list[dict[str, Any]]] = {}
        for row in rows:
            by_repeat.setdefault(row.get(REPEAT_KEY, 0), []).append(row)
        per_repeat = [m for m in (self.pair_metrics(group) for group in by_repeat.values()) if m]
        if not per_repeat:
            return {}
        return {key: sum(m[key] for m in per_repeat) / len(per_repeat) for key in per_repeat[0]}
