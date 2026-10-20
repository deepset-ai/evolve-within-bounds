# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
`run_tool` and `trial_scan` for the optimizer: try the draft's code on a TRAINING pair before submitting it.

- **A tool** runs once with the given arguments on the pair's vulnerable repository. Its model calls are real, at most
  `EXAMPLE_CALLS`.
- **A step** runs on both repositories. Its input is what the agent reported in the draft's latest run.
- **A trial scan** runs the whole draft on both repositories, as a measurement would.

The repositories are the same leak-free staged copies a scan sees. With a sandbox, the code runs inside it
(`security_agent.synthetic.sandbox`); the benchmark, its answer key and the planted lines stay on the host, where the
report for the optimizer is assembled. Only training pairs are accepted.
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from security_agent.synthetic.agent import AgentScanner, Llm, ScanContext, _findings_in, call_with_timeout, load_code
from security_agent.synthetic.bench.adapters import load_benchmark
from security_agent.synthetic.bench.pairs import load_pairs, pair_targets
from security_agent.synthetic.codecheck import check_code
from security_agent.synthetic.gateway import ModelGateway
from security_agent.synthetic.staging import stage

MAX_SHOWN = 25
EXAMPLE_CALLS, EXAMPLE_TOKENS = 12, 30_000
TRIAL_NEAR = 10  # findings within this many lines of the planted lines are shown


def _short(f: dict) -> dict:
    return {k: f.get(k) for k in ("id", "path", "line_start", "line_end", "cwe", "confidence", "title")}


def _step_report(before: list[dict], after: list[dict], gateway: ModelGateway, error: str | None) -> dict:
    by_id = {f["id"]: f for f in before}
    kept_ids = {f.get("id") for f in after if f.get("id") in by_id}
    changed = [
        _short(f)
        for f in after
        if f.get("id") in by_id
        and any(f.get(k) != by_id[f["id"]].get(k) for k in ("line_start", "line_end", "cwe", "confidence", "title"))
    ]
    added = [_short(f) for f in after if f.get("id") not in by_id]
    calls = gateway.calls
    return {
        "ok": error is None,
        "input": len(before),
        "output": len(after),
        "dropped": [_short(f) for f in before if f["id"] not in kept_ids][:MAX_SHOWN],
        "changed": changed[:MAX_SHOWN],
        "added": added[:MAX_SHOWN],
        "call_errors": [c.get("error") or c.get("json_error") for c in calls if c.get("error") or c.get("json_error")][
            :3
        ],
        **({"error": str(error)[-1200:]} if error else {}),
    }


def run_member(
    path: Path,
    kind: str,
    root: str,
    files: list[str],
    model: dict,
    arguments: dict | None = None,
    reported: list[dict] | None = None,
) -> dict[str, Any]:
    """
    Run one tool (with `arguments`) or one step (on `reported`, the agent's findings) on one staged repository.

    This executes the optimizer's code; with a sandbox it runs there (`security_agent.synthetic.sandbox`).
    """
    ctx = ScanContext(root, files)
    gateway = ModelGateway(model, EXAMPLE_CALLS, EXAMPLE_TOKENS)
    ctx.llm = Llm(gateway)
    started = time.monotonic()
    if kind == "tool":
        module = load_code(path)
        try:
            value = call_with_timeout(lambda: module.run(ctx, **(arguments or {})), 300)
            text = value if isinstance(value, str) else json.dumps(value, default=str, indent=1)
            result: dict[str, Any] = {
                "ok": True,
                "output": text[:6_000] + (f"\n... [{len(text) - 6_000} more characters]" if len(text) > 6_000 else ""),
            }
        except Exception as exc:  # noqa: BLE001 - shown to the optimizer
            result = {"ok": False, "error": "".join(traceback.format_exception(exc))[-1_500:]}
        if ctx.findings:
            result["reported"] = [_short(f) for f in ctx.findings][:MAX_SHOWN]
    else:
        ctx.findings = _findings_in(reported or [], ctx)
        before = [dict(f) for f in ctx.findings]
        module = load_code(path)
        error = None
        try:
            call_with_timeout(lambda: module.run(ctx), 900)
        except Exception as exc:  # noqa: BLE001 - shown to the optimizer
            error = "".join(traceback.format_exception(exc))[-1_500:]
        result = _step_report(before, [dict(f) for f in ctx.findings], gateway, error)
    result["seconds"] = round(time.monotonic() - started, 2)
    result["model_calls"] = len(gateway.calls)
    result["output_tokens"] = sum(int(c.get("completion_tokens", 0)) for c in gateway.calls)
    return result


class Examples:
    """
    `run_tool` and `trial_scan` on training pairs.

    :param train: the training pairs, `{benchmark: [pair_id, ...]}`.
    :param base_records: `(benchmark, instance_id)` -> the draft's latest record of that instance, or None.
    :param model: the model config.
    :param sandbox: an `security_agent.synthetic.sandbox.OpenShell`; the draft's code then runs inside it.
    """

    def __init__(
        self,
        train: dict[str, list[str]],
        base_records: Callable[[str, str], dict | None],
        *,
        model: dict | None = None,
        bench_loader: Callable[[str], Any] = load_benchmark,
        prefill_tps: float = 3000.0,
        decode_tps: float = 110.0,
        sandbox: Any = None,
    ) -> None:
        self.train = {name: set(ids) for name, ids in train.items()}
        self.base_records = base_records
        self.model = model or {}
        self.bench_loader = bench_loader
        self.prefill_tps, self.decode_tps = prefill_tps, decode_tps
        self.sandbox = sandbox
        self._pairs: dict[str, dict[str, dict]] = {}

    def _pair(self, benchmark: str, pair_id: str) -> dict:
        if benchmark not in self._pairs:
            self._pairs[benchmark] = load_pairs(self.bench_loader(benchmark))
        return self._pairs[benchmark][pair_id]

    def _check_example(self, example: str) -> tuple[str, str] | str:
        benchmark, _, pair_id = example.strip().partition("/")
        if pair_id not in self.train.get(benchmark, set()):
            some = [f"{b}/{p}" for b, ids in sorted(self.train.items()) for p in sorted(ids)[:4]]
            return json.dumps(
                {
                    "ok": False,
                    "error": f"'{example}' is not a training pair key. Use one from the list 'Training pair keys' "
                    f"in your context, or from the digests, e.g. {', '.join(some)}",
                }
            )
        return benchmark, pair_id

    def _planted(self, pair: dict) -> list[dict]:
        return [
            {
                "path": t["path"],
                "vulnerable_lines": [t["mutant_line_start"], t["mutant_line_end"]],
                "safe_twin_lines": [t["baseline_line_start"], t["baseline_line_end"]],
            }
            for t in pair_targets(pair)
        ]

    def __call__(self, tools_dir: Path, name: str, example: str, arguments: dict | None = None) -> str:
        """`run_tool`: one code file of the draft on a training pair."""
        checked = self._check_example(example)
        if isinstance(checked, str):
            return checked
        benchmark, pair_id = checked
        path = Path(tools_dir) / f"{name}.py"
        kind, problems = check_code(path)
        if problems or kind is None:
            return json.dumps({"ok": False, "errors": problems})
        pair = self._pair(benchmark, pair_id)
        paths = {i.instance_id: i.path for i in self.bench_loader(benchmark).instances()}
        report: dict[str, Any] = {"ok": True, "tool": name, "kind": kind, "planted": self._planted(pair)}
        members = (
            [("vulnerable", "mutant_instance_id")]
            if kind == "tool"
            else [("vulnerable", "mutant_instance_id"), ("safe_twin", "baseline_instance_id")]
        )
        for member, key in members:
            reported = None
            if kind == "step":
                record = self.base_records(benchmark, pair[key]) or {}
                reported = (record.get("agent") or {}).get("reported", record.get("candidates", []))
            staged = stage(paths[pair[key]])
            try:
                if self.sandbox is not None:
                    report[member] = self.sandbox.run_member(path, kind, staged, self.model, arguments, reported)
                else:
                    report[member] = run_member(
                        path, kind, str(staged.root), list(staged.files), self.model, arguments, reported
                    )
            finally:
                staged.cleanup()
        report["note"] = f"model calls are real, at most {EXAMPLE_CALLS} per repository here" + (
            "; a step's input is what the agent reported in the draft's latest run" if kind == "step" else ""
        )
        text = json.dumps(report, indent=1)
        return text if len(text) <= 12_000 else text[:12_000] + "\n... [truncated]"

    def trial(self, candidate_dir: Path, example: str) -> str:
        """`trial_scan`: scan one training pair with the whole draft."""
        checked = self._check_example(example)
        if isinstance(checked, str):
            return checked
        benchmark, pair_id = checked
        pair = self._pair(benchmark, pair_id)
        paths = {i.instance_id: i.path for i in self.bench_loader(benchmark).instances()}
        try:
            scanner: Any = AgentScanner(candidate_dir, model_config=self.model)
        except ValueError as exc:
            return json.dumps({"ok": False, "error": str(exc)[:2_000]})
        if self.sandbox is not None:
            from security_agent.synthetic.sandbox import SandboxScanner

            scanner = SandboxScanner(scanner, self.sandbox)
        targets = pair_targets(pair)

        def scan(member: str, key: str) -> dict:
            staged = stage(paths[pair[key]])
            try:
                result = scanner.scan(staged)
            finally:
                staged.cleanup()
            if result.record is None:
                raise RuntimeError(result.error or "the scan returned no record")
            side = "mutant" if member == "vulnerable" else "baseline"
            near = [
                _short({**f.model_dump(), "id": None})
                for f in result.findings
                for t in targets
                if f.path == t["path"]
                and f.line_start <= t[f"{side}_line_end"] + TRIAL_NEAR
                and f.line_end >= t[f"{side}_line_start"] - TRIAL_NEAR
            ]
            hit = any(
                f.path == t["path"]
                and f.line_start <= t[f"{side}_line_end"] + 2
                and f.line_end >= t[f"{side}_line_start"] - 2
                for f in result.findings
                for t in targets
            )
            agent = result.record["agent"]
            return {
                ("flagged_at_planted_lines" if member == "vulnerable" else "flagged_at_corresponding_lines"): hit,
                "findings": len(result.findings),
                f"findings_within_{TRIAL_NEAR}_lines": near[:MAX_SHOWN],
                "agent": {
                    "stop": agent["stop"],
                    "steps": agent["steps"],
                    "tool_calls": _counts(agent["tool_calls"]),
                    "tool_errors": [c.get("error") for c in agent["tool_calls"] if not c.get("ok")][:3],
                    "code_load_errors": agent["load_errors"][:3],
                    "read_planted_file": any(r["path"] in {t["path"] for t in targets} for r in agent["reads"]),
                },
                "steps": [
                    {
                        "step": s["component"],
                        "ok": s["ok"],
                        "input": s["input"],
                        "kept": s["kept"],
                        "error": (s["error"] or "")[-600:] or None,
                    }
                    for s in result.record["components"]
                ],
                "seconds": round(result.cost.seconds, 1),
                "gpu_minutes_estimate": round(
                    (
                        (result.cost.prompt_tokens - _cached(result.record)) / self.prefill_tps
                        + result.cost.completion_tokens / self.decode_tps
                    )
                    / 60,
                    2,
                ),
            }

        with cf.ThreadPoolExecutor(max_workers=2) as pool:
            jobs = {
                member: pool.submit(scan, member, key)
                for member, key in (("vulnerable", "mutant_instance_id"), ("safe_twin", "baseline_instance_id"))
            }
            report: dict[str, Any] = {"ok": True, "pair": example, "planted": self._planted(pair)}
            for member, job in jobs.items():
                try:
                    report[member] = job.result()
                except Exception as exc:  # noqa: BLE001 - shown to the optimizer
                    report[member] = {"error": "".join(traceback.format_exception(exc))[-1_500:]}
        right = report.get("vulnerable", {}).get("flagged_at_planted_lines") and not report.get("safe_twin", {}).get(
            "flagged_at_corresponding_lines"
        )
        report["pair_right"] = bool(right)
        text = json.dumps(report, indent=1)
        return text if len(text) <= 12_000 else text[:12_000] + "\n... [truncated]"


def _cached(record: dict) -> int:
    from security_agent.synthetic.measure import record_cost

    return record_cost(record).get("cached_tokens", 0)


def _counts(calls: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for c in calls:
        out[c.get("tool", "?")] = out.get(c.get("tool", "?"), 0) + 1
    return out
