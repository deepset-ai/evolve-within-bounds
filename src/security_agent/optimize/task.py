# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
What the loop needs from a benchmark: the `Task` interface.

The loop (`security_agent.optimize.loop`) knows candidates, pairs, measurements, gates and the optimizer. Everything
that depends on what the agent does and how the benchmark scores it comes from the task:

- measuring a candidate on pairs, with the early abort between parts;
- rendering the failure digests for the optimizer, and the material they show (for the leakage check);
- the workspace's checks and tools: the candidate contract, the contract test of its code, trying code on a training
  pair, reading what the agent did;
- the text that explains the scoring, and the unit the gates count per (a repository, a function);
- repairing measurements that a model-server outage spoiled.

`security_agent.synthetic.task.SyntheticTask` is the task for the synthetic custom-component benchmark.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from security_agent.optimize.measurement import Measurement


class Task(Protocol):
    """A benchmark, as the loop sees it."""

    name: str
    unit: str  # what a measurement's instances are, e.g. "repository"

    def measure(
        self,
        candidate: Path,
        parts: list[dict[str, list[str]]],
        out_dir: Path,
        *,
        label: str,
        abort: Callable[[Measurement], bool] | None = None,
    ) -> Measurement:
        """Measure `candidate` on `parts` (the pairs, in parts); `abort` is checked between parts."""
        ...

    def render(self, digest: dict[str, Any]) -> str:
        """One failure digest as text for the optimizer."""
        ...

    def shown_material(self, digests: list[dict[str, Any]]) -> dict[str, list[str]]:
        """What the digests show (paths, repositories, titles, code), for the leakage check."""
        ...

    def training_material(self, train: dict[str, list[str]]) -> dict[str, list[str]]:
        """What identifies the training pairs beyond the digests, for the leakage check."""
        ...

    def scoring(self) -> str:
        """How a pair is scored, in one or two sentences."""
        ...

    def workspace_options(
        self,
        train: dict[str, list[str]],
        best: Callable[[], Measurement | None],
        on_shown: Callable[[dict[str, list[str]]], None],
    ) -> dict[str, Any]:
        """
        Keyword arguments for `Workspace`: its checks and the task's tools.

        `check`, `contract_check`, `example_runner`, `trial_runner`, `reasoning_reader`, `tool_specs`. `best()`
        returns the measurement of the current best candidate; `on_shown` receives what the tools show, for the leakage
        check.
        """
        ...

    def spoiled(self, measurement: Measurement) -> int:
        """
        Drop what a model-server outage spoiled in `measurement`'s runs; how many instances will be measured again.

        Measuring the candidate again then redoes only those. 0: nothing to repair.
        """
        ...
