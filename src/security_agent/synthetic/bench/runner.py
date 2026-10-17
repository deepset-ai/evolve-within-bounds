# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Run a scanner over a benchmark: stage each instance, scan it, journal the report, export predictions.

A run directory holds:
- `manifest.json`: the benchmark, the scanner's full description, the selection, and timestamps;
- `reports.jsonl`: the journal, one `ScanReport` per line, appended as scans finish;
- `records/<id>.json`: optional per-scan records (trajectories);
- `predictions.jsonl`: the benchmark export, one line per selected instance.

Runs are resumable. Instances with a complete report are skipped, and incomplete ones are retried unless
`retry_incomplete=False`. The latest journal line for an instance wins.

Run directories live under the gitignored `runs/`.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_agent import __version__
from security_agent.synthetic.bench.adapters import Benchmark, Instance
from security_agent.synthetic.export import ExportStats, write_predictions
from security_agent.synthetic.scan import Scanner
from security_agent.synthetic.schema import ScanReport
from security_agent.synthetic.staging import stage


class RunError(RuntimeError):
    pass


@dataclass
class RunSummary:
    run_dir: Path
    selected: int
    scanned: int
    skipped: int
    complete: int
    incomplete: int
    export: ExportStats
    subset: bool
    seconds: float
    verdicts: dict[str, int] = field(default_factory=dict)


def load_journal(path: Path) -> dict[str, ScanReport]:
    """The latest report per instance in a run's journal."""
    reports: dict[str, ScanReport] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                report = ScanReport.model_validate_json(line)
                reports[report.instance_id] = report
    return reports


def select(
    instances: list[Instance], limit: int | None = None, instance_ids: list[str] | None = None
) -> list[Instance]:
    """The instances to scan: all, the given ids, or the first `limit`."""
    if instance_ids:
        wanted = set(instance_ids)
        unknown = wanted - {i.instance_id for i in instances}
        if unknown:
            raise RunError(f"unknown instance ids: {', '.join(sorted(unknown))}")
        instances = [i for i in instances if i.instance_id in wanted]
    return instances[:limit] if limit else instances


def run(
    benchmark: Benchmark,
    scanner: Scanner,
    run_dir: Path,
    *,
    concurrency: int = 8,
    limit: int | None = None,
    instance_ids: list[str] | None = None,
    retry_incomplete: bool = True,
    keep_staging: bool = False,
    log: Callable[..., None] = print,
) -> RunSummary:
    """Scan a benchmark's instances, journal the reports and export the predictions (see the module docstring)."""
    started = time.monotonic()
    all_instances = benchmark.instances()
    selected = select(all_instances, limit, instance_ids)
    subset = len(selected) < len(all_instances)
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_manifest(run_dir, benchmark, scanner, selected, subset)

    journal_path = run_dir / "reports.jsonl"
    journal = load_journal(journal_path)
    todo = [
        inst
        for inst in selected
        if inst.instance_id not in journal or (retry_incomplete and journal[inst.instance_id].status != "complete")
    ]
    skipped = len(selected) - len(todo)
    if skipped:
        log(f"resuming: {skipped} of {len(selected)} instances already done")

    lock = threading.Lock()
    stage_parent = run_dir / "staging" if keep_staging else None
    done = 0

    def work(inst: Instance) -> ScanReport:
        t0 = time.monotonic()
        staged = None
        try:
            staged = stage(inst.path, stage_parent)
            if keep_staging:
                with lock, (run_dir / "staging" / "index.jsonl").open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps({"instance_id": inst.instance_id, "root": str(staged.root)}) + "\n")
            result = scanner.scan(staged)
            if result.cost.seconds == 0.0:
                result.cost.seconds = round(time.monotonic() - t0, 3)
            report = ScanReport.from_result(inst.instance_id, scanner.name, result)
            if result.record is not None:
                records = run_dir / "records"
                records.mkdir(exist_ok=True)
                (records / f"{inst.instance_id}.json").write_text(json.dumps(result.record, indent=1), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001 - every failure becomes an incomplete report, never a missing line
            report = ScanReport.failed(
                inst.instance_id, scanner.name, f"{type(exc).__name__}: {exc}", round(time.monotonic() - t0, 3)
            )
        finally:
            if staged is not None and not keep_staging:
                staged.cleanup()
        return report

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {pool.submit(work, inst): inst for inst in todo}
        for future in as_completed(futures):
            report = future.result()
            with lock:
                with journal_path.open("a", encoding="utf-8") as handle:
                    handle.write(report.model_dump_json() + "\n")
                journal[report.instance_id] = report
                done += 1
            log(
                f"[{done}/{len(todo)}] {report.instance_id} {report.status} "
                f"{len(report.findings)} findings {report.cost.seconds:.1f}s"
                + (f" error={report.error}" if report.error else "")
            )

    reports = [journal[i.instance_id] for i in selected if i.instance_id in journal]
    export = write_predictions(reports, [i.instance_id for i in selected], run_dir / "predictions.jsonl")
    verdicts: dict[str, int] = {}
    for report in reports:
        verdicts[report.verdict] = verdicts.get(report.verdict, 0) + 1
    complete = sum(1 for r in reports if r.status == "complete")
    return RunSummary(
        run_dir=run_dir,
        selected=len(selected),
        scanned=len(todo),
        skipped=skipped,
        complete=complete,
        incomplete=len(reports) - complete,
        export=export,
        subset=subset,
        seconds=round(time.monotonic() - started, 1),
        verdicts=verdicts,
    )


def _write_manifest(
    run_dir: Path, benchmark: Benchmark, scanner: Scanner, selected: list[Instance], subset: bool
) -> None:
    path = run_dir / "manifest.json"
    now = datetime.now(UTC).isoformat(timespec="seconds")
    description = scanner.describe()
    selection = [i.instance_id for i in selected]
    if path.is_file():
        manifest: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        if manifest.get("benchmark") != benchmark.name or manifest.get("scanner") != description:
            raise RunError(
                f"{run_dir} belongs to a different run ({manifest.get('benchmark')}, "
                f"{manifest.get('scanner', {}).get('name')}); use a new --run-dir"
            )
        if manifest.get("selection") != selection:
            raise RunError(f"{run_dir} was started with a different instance selection; use a new --run-dir")
        manifest.setdefault("resumed", []).append(now)
    else:
        manifest = {
            "benchmark": benchmark.name,
            "benchmark_root": str(benchmark.root),
            "scanner": description,
            "security_agent_version": __version__,
            "python": sys.version.split()[0],
            "subset": subset,
            "selection": selection,
            "created": now,
        }
    path.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
