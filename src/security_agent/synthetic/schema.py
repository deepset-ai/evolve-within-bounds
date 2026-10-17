# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The scan result contract.

`ScanResult` is what a scanner returns. `ScanReport` is what the runner journals: the result plus the instance id,
which the scanner never sees.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class Finding(BaseModel):
    path: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    cwe: str = Field(pattern=r"^CWE-[1-9]\d*$")
    title: str
    severity: Literal["high", "medium", "low"] | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    source: str | None = None
    sink: str | None = None
    missing_control: str | None = None
    evidence: str | None = None
    fix: str | None = None

    @model_validator(mode="after")
    def _span(self) -> "Finding":
        if self.line_end < self.line_start:
            raise ValueError(f"line_end {self.line_end} < line_start {self.line_start}")
        return self


class Coverage(BaseModel):
    files: int = 0
    reviewed: int = 0
    skipped: list[str] = Field(default_factory=list)


class Cost(BaseModel):
    seconds: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0


class ScanResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    cost: Cost = Field(default_factory=Cost)
    complete: bool = True
    error: str | None = None
    # Free-form per-scan record (trajectories, raw model output); written next to the journal, not exported.
    record: dict[str, Any] | None = None


class ScanReport(BaseModel):
    instance_id: str
    status: Literal["complete", "incomplete"]
    verdict: Literal["vulnerable", "no_findings", "incomplete"]
    findings: list[Finding] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    cost: Cost = Field(default_factory=Cost)
    error: str | None = None
    scanner: str

    @classmethod
    def from_result(cls, instance_id: str, scanner: str, result: ScanResult) -> "ScanReport":
        """The report of a scan's result."""
        status: Literal["complete", "incomplete"] = (
            "complete" if result.complete and result.error is None else "incomplete"
        )
        verdict: Literal["vulnerable", "no_findings", "incomplete"] = (
            "incomplete" if status == "incomplete" else ("vulnerable" if result.findings else "no_findings")
        )
        findings = sorted(result.findings, key=lambda f: -(f.confidence if f.confidence is not None else -1))
        return cls(
            instance_id=instance_id,
            status=status,
            verdict=verdict,
            findings=findings,
            coverage=result.coverage,
            cost=result.cost,
            error=result.error,
            scanner=scanner,
        )

    @classmethod
    def failed(cls, instance_id: str, scanner: str, error: str, seconds: float = 0.0) -> "ScanReport":
        """The report of a scan that failed."""
        return cls(
            instance_id=instance_id,
            status="incomplete",
            verdict="incomplete",
            error=error,
            scanner=scanner,
            cost=Cost(seconds=seconds),
        )
