# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The scanner interface.

A scanner sees only a `StagedRepo`. It never sees the instance id, the benchmark or the host path of the original
instance; the runner attaches the instance id to its result afterwards.
"""

from __future__ import annotations

from typing import Any, Protocol

from security_agent.synthetic.schema import Coverage, ScanResult
from security_agent.synthetic.staging import StagedRepo


class Scanner(Protocol):
    """What the runner needs from a scanner."""

    name: str

    def describe(self) -> dict[str, Any]:
        """Everything that determines the scanner's behaviour, recorded in the run manifest."""
        ...

    def scan(self, repo: StagedRepo) -> ScanResult:
        """Scan one staged repository."""
        ...


class EmptyScanner:
    """Reports nothing. Checks the plumbing end to end: every benchmark metric must come out at its floor."""

    name = "empty"

    def describe(self) -> dict[str, Any]:
        """Its name."""
        return {"name": self.name}

    def scan(self, repo: StagedRepo) -> ScanResult:
        """Report nothing."""
        return ScanResult(coverage=Coverage(files=len(repo.files), reviewed=0))
