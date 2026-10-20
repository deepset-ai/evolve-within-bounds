# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
What a task's measurement of a candidate returns to the loop.

- **Outcomes** are keyed `<benchmark>/<pair_id>` as `[strict, right]`. `right` is the loop's objective. `strict` is a
  stricter reading the task may report alongside (for a scanner: right and with the right weakness category).
- **Cost** is the model tokens the candidate spent: `prompt_tokens`, `cached_tokens` (prompt tokens served from the
  model server's prefix cache), `completion_tokens` and `calls`.
- **Instances** are the items scanned or classified; the gates' limits are per instance.
- **Incomplete** instances could not be measured because the model server failed; **tool_errors** counts instances on
  which the candidate's own code failed.
- **Digests** describe the training pairs the candidate gets wrong, for the optimizer. Each is a dict with at least
  `key` and `labels`; the task renders them.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Measurement:
    """One measurement of one candidate on a set of pairs."""

    label: str
    outcomes: dict[str, list[bool]] = field(default_factory=dict)
    cost: dict[str, int] = field(
        default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0, "cached_tokens": 0}
    )
    instances: int = 0
    incomplete: int = 0
    seconds: float = 0.0
    aborted: bool = False
    abort_reason: str = ""
    tool_errors: int = 0
    findings: int = 0
    run_dirs: list[str] = field(default_factory=list)
    digests: list[dict] = field(default_factory=list)

    @property
    def pairs(self) -> int:
        """How many pairs were measured."""
        return len(self.outcomes)

    @property
    def strict(self) -> int:
        """Pairs right in the strict reading."""
        return sum(1 for strict, _ in self.outcomes.values() if strict)

    @property
    def right(self) -> int:
        """Pairs right: the loop's objective."""
        return sum(1 for _, right in self.outcomes.values() if right)

    def count(self, keys: Iterable[str]) -> tuple[int, int]:
        """(strict, right) over the given pair keys."""
        keys = [k for k in keys if k in self.outcomes]
        return sum(1 for k in keys if self.outcomes[k][0]), sum(1 for k in keys if self.outcomes[k][1])

    def to_dict(self, digests: bool = False) -> dict[str, Any]:
        """For the journal; digests are kept in their own file."""
        out = asdict(self)
        if not digests:
            out.pop("digests")
        out.update(pairs=self.pairs, strict=self.strict, right=self.right)
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Measurement:
        """Back from the journal."""
        names = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in names})
