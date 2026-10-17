# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Export to the benchmark prediction format.

There is exactly one JSONL line per expected instance, in the given order, with the five fields the scorers
read. A finding the scorer would reject is dropped and counted rather than written. A rejected finding
aborts the whole scoring run (a bad CWE, a non-positive line, an inverted span, a `..` path).
An instance with no report is written with `findings: []` and also counted, so a crash never looks clean.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from security_agent.synthetic.schema import ScanReport

_CWE = re.compile(r"^CWE-[1-9]\d*$")


@dataclass
class ExportStats:
    instances: int = 0
    findings: int = 0
    dropped: dict[str, int] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)

    def drop(self, reason: str) -> None:
        """Count one dropped finding under its reason."""
        self.dropped[reason] = self.dropped.get(reason, 0) + 1


def benchmark_path(path: str) -> str | None:
    """Repository-relative POSIX path as the scorers compare it; None if unusable."""
    text = path.strip().replace("\\", "/")
    for prefix in ("/repo/", "./", "/"):
        while text.startswith(prefix):
            text = text[len(prefix) :]
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def benchmark_record(report: ScanReport, stats: ExportStats) -> dict:
    """One instance's line of the benchmark export."""
    findings = []
    for finding in report.findings:
        path = benchmark_path(finding.path)
        if path is None:
            stats.drop("bad_path")
            continue
        if not _CWE.match(finding.cwe):
            stats.drop("bad_cwe")
            continue
        if finding.line_start < 1 or finding.line_end < finding.line_start:
            stats.drop("bad_span")
            continue
        findings.append(
            {
                "path": path,
                "line_start": finding.line_start,
                "line_end": finding.line_end,
                "cwe": finding.cwe,
                "title": finding.title,
            }
        )
    stats.findings += len(findings)
    return {"instance_id": report.instance_id, "findings": findings}


def write_predictions(reports: Iterable[ScanReport], expected_ids: list[str], path: Path) -> ExportStats:
    """Write the benchmark export: one line per expected instance."""
    by_id = {report.instance_id: report for report in reports}
    stats = ExportStats()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for instance_id in expected_ids:
            report = by_id.get(instance_id)
            if report is None:
                stats.missing.append(instance_id)
                record = {"instance_id": instance_id, "findings": []}
            else:
                if report.status != "complete":
                    stats.incomplete.append(instance_id)
                record = benchmark_record(report, stats)
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            stats.instances += 1
    return stats
