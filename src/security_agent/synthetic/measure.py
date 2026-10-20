# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Measuring a candidate on a set of pairs: scan both repositories of every pair, score them, sum the cost.

- **Parts.** The pairs can be split into parts (the training halves). Each part is a separate run directory per
  benchmark, `<out>/<benchmark>-part<k>`. After a part, `abort` may stop the measurement: the early-abort gate.
- **Outcomes.** Each part is scored by the benchmark's own scorer, and only the part's pairs are counted. Outcomes are
  keyed `<benchmark>/<pair_id>` as `[strict, right]`: right with a matching CWE, and right at the right lines whatever
  the CWE (the loop's objective).
- **Cost** is the model tokens the candidate spends on these instances, from the scan records: the agent's calls, its
  tools' calls and its steps' calls. Prompt tokens served from the server's prefix cache are counted separately.
- **Findings** is the number of findings reported on these instances.
- **Digests** are built for the pairs that fail the objective (`security_agent.synthetic.digest`).
- **Sandbox.** With `sandbox`, every scan runs inside that OpenShell sandbox
  (`security_agent.synthetic.sandbox.SandboxScanner`).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from security_agent.optimize.measurement import Measurement
from security_agent.synthetic.agent import AgentScanner
from security_agent.synthetic.bench.adapters import load_benchmark
from security_agent.synthetic.bench.pairs import load_pairs
from security_agent.synthetic.bench.runner import load_journal, run
from security_agent.synthetic.digest import build_digests


def record_cost(record: dict[str, Any]) -> dict[str, int]:
    """Tokens and calls of one scan record: the agent's calls, its tools' calls and its steps' calls."""
    agent = record.get("agent") or {}
    calls = [c for c in agent.get("calls", []) + agent.get("code_calls", []) if "error" not in c]
    calls += [c for step in record.get("components", []) for c in step.get("calls", []) if "error" not in c]
    return {
        "prompt_tokens": sum(int(c.get("prompt_tokens", 0)) for c in calls),
        "completion_tokens": sum(int(c.get("completion_tokens", 0)) for c in calls),
        "calls": len(calls),
        "cached_tokens": sum(int(c.get("cached_tokens", 0)) for c in calls),
    }


def measure(
    candidate: Path,
    parts: list[dict[str, list[str]]],
    out_dir: Path,
    *,
    label: str,
    abort: Callable[[Measurement], bool] | None = None,
    digests: bool = True,
    model_config: str | dict | None = None,
    concurrency: int = 8,
    log: Callable[[str], None] = print,
    bench_loader: Callable[[str], Any] = load_benchmark,
    sandbox: Any = None,
) -> Measurement:
    """Measure `candidate` on `parts`; the early abort is checked between parts."""
    started = time.monotonic()
    m = Measurement(label=label)
    for k, part in enumerate(parts, 1):
        for name, pair_ids in part.items():
            if not pair_ids:
                continue
            bench = bench_loader(name)
            bench.prepare()
            ids = bench.pair_instances(pair_ids)
            run_dir = out_dir / f"{name}-part{k}"
            scanner: Any = AgentScanner(candidate, model_config=model_config)
            if sandbox is not None:
                from security_agent.synthetic.sandbox import SandboxScanner

                scanner = SandboxScanner(scanner, sandbox)
            log(f"  [{label}] {name} part {k}: {len(pair_ids)} pairs, {len(ids)} instances")
            summary = run(bench, scanner, run_dir, instance_ids=ids, concurrency=concurrency, log=lambda *_: None)
            report = bench.score(run_dir / "predictions.jsonl", run_dir / "score.json", allow_missing=True)
            m.run_dirs.append(str(run_dir))
            m.instances += summary.selected
            m.incomplete += summary.incomplete
            journal = load_journal(run_dir / "reports.jsonl")
            m.findings += sum(len(journal[iid].findings) for iid in ids if iid in journal)
            for iid in ids:
                record = run_dir / "records" / f"{iid}.json"
                if record.is_file():
                    data = json.loads(record.read_text(encoding="utf-8"))
                    for key, value in record_cost(data).items():
                        m.cost[key] = m.cost.get(key, 0) + value
                    if any(not step.get("ok") for step in data.get("components", [])):
                        m.tool_errors += 1
            wanted = set(pair_ids)
            rows = [r for r in report["pair_results"] if r["pair_id"] in wanted]
            for r in rows:
                m.outcomes[f"{name}/{r['pair_id']}"] = [bool(r["pair_correct"]), bool(r["pair_localized_correct"])]
            if digests:
                paths = {i.instance_id: i.path for i in bench.instances()}
                m.digests += build_digests(name, run_dir, rows, load_pairs(bench), paths)
        log(f"  [{label}] after part {k}: {m.right}/{m.pairs} pairs right (any CWE), {m.strict} with the right CWE")
        if abort is not None and k < len(parts) and abort(m):
            m.aborted = True
            break
    m.seconds = round(time.monotonic() - started, 1)
    return m


def drop_outage_instances(run_dir: Path) -> int:
    """
    Drop the instances of a run directory that a model-server outage touched (their record and journal line).

    A resumed run then scans them again. Returns how many were dropped.
    """
    journal = run_dir / "reports.jsonl"
    if not journal.is_file():
        return 0
    spoiled = set()
    for record_path in (run_dir / "records").glob("*.json"):
        record = json.loads(record_path.read_text(encoding="utf-8"))
        steps = record.get("components", [])
        if (record.get("agent") or {}).get("outage") or any(c.get("outage") for s in steps for c in s.get("calls", [])):
            spoiled.add(record_path.stem)
    if not spoiled:
        return 0
    lines = [
        line
        for line in journal.read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line)["instance_id"] not in spoiled
    ]
    tmp = journal.with_suffix(".jsonl.tmp")
    tmp.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    tmp.replace(journal)
    for stem in spoiled:
        (run_dir / "records" / f"{stem}.json").unlink()
    return len(spoiled)


def journal_lines(run_dir: Path) -> int:
    """How many scans a run directory's journal holds."""
    journal = run_dir / "reports.jsonl"
    if not journal.is_file():
        return 0
    return sum(1 for line in journal.read_text(encoding="utf-8").splitlines() if line.strip())


def spoiled(m: Measurement) -> int:
    """Drop what an outage spoiled in a measurement's runs; how many scans will run again (dropped or missing)."""
    dropped = sum(drop_outage_instances(Path(d)) for d in m.run_dirs)
    missing = m.instances - sum(journal_lines(Path(d)) for d in m.run_dirs)
    return max(dropped, missing, 0)


def record(m: Measurement | None, benchmark: str, instance_id: str) -> dict[str, Any] | None:
    """A measurement's scan record of one instance, or None."""
    for run_dir in m.run_dirs if m else []:
        path = Path(run_dir) / "records" / f"{instance_id}.json"
        if Path(run_dir).name.startswith(benchmark) and path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    return None
