# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The scanner's output stage: clean and deduplicate the findings before they are reported.

`Normalizer` is the last component of every candidate pipeline. For each finding it:
- normalizes the CWE (`CWE-89`) and drops findings without one;
- makes the path repository-relative and drops findings in files the repository does not have;
- clamps the lines to the file;
- keeps one finding per location: of overlapping findings, the most confident wins, whatever its CWE;
- drops findings below the confidence threshold `tau` (0 keeps everything).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from haystack import component

from security_agent.synthetic.cwe import normalize_cwe
from security_agent.synthetic.export import benchmark_path


@component
class Normalizer:
    def __init__(self, tau: int = 50, max_per_location: int = 1) -> None:
        self.tau = tau
        self.max_per_location = max_per_location

    @component.output_types(findings=list[dict], stats=dict)
    def run(self, candidates: list[dict], root: str, files: list[str]) -> dict[str, Any]:
        """Validate, deduplicate and threshold the candidates (see the module docstring)."""
        known = set(files)
        line_counts: dict[str, int] = {}
        stats = {
            "candidates": len(candidates),
            "no_cwe": 0,
            "unverifiable": 0,
            "duplicate_location": 0,
            "below_tau": 0,
            "kept": 0,
        }
        cleaned = []
        for cand in candidates:
            cwe = normalize_cwe(cand.get("cwe"))
            path = benchmark_path(str(cand.get("path", "")))
            if cwe is None:
                stats["no_cwe"] += 1
                continue
            if path is None or path not in known:
                stats["unverifiable"] += 1
                continue
            if path not in line_counts:
                line_counts[path] = len((Path(root) / path).read_text(encoding="utf-8", errors="replace").splitlines())
            n = line_counts[path]
            start, end = sorted((int(cand["line_start"]), int(cand["line_end"])))
            if start > n:
                stats["unverifiable"] += 1
                continue
            confidence = int(cand.get("confidence", 50))
            cleaned.append(
                {
                    **cand,
                    "path": path,
                    "cwe": cwe,
                    "line_start": max(1, start),
                    "line_end": min(end, n),
                    "confidence": confidence,
                }
            )
        # One finding per location: the most confident finding wins an overlap, whatever its CWE. With
        # max_per_location > 1, up to that many overlapping findings survive if their CWEs differ.
        cleaned.sort(key=lambda c: -c["confidence"])
        kept: list[dict] = []
        for cand in cleaned:
            overlapping = [
                k
                for k in kept
                if k["path"] == cand["path"]
                and k["line_start"] <= cand["line_end"]
                and cand["line_start"] <= k["line_end"]
            ]
            if overlapping and (
                len(overlapping) >= self.max_per_location or any(k["cwe"] == cand["cwe"] for k in overlapping)
            ):
                stats["duplicate_location"] += 1
                continue
            kept.append(cand)
        findings = [c for c in kept if c["confidence"] >= self.tau]
        stats["below_tau"] = len(kept) - len(findings)
        stats["kept"] = len(findings)
        return {"findings": findings, "stats": stats}
