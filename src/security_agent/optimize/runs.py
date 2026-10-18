# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""Experiment directories: claiming a new one, and summarizing one's journal (`loop status`)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path


def claim_run_dir(parent: Path, prefix: str) -> Path:
    """Create and return `<parent>/<prefix><n>` for the first free n."""
    parent.mkdir(parents=True, exist_ok=True)
    n = 1
    while True:
        candidate = parent / f"{prefix}{n}"
        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            n += 1


def status_lines(run_dir: Path) -> Iterator[str]:
    """One line per event of an experiment's journal that a person wants to see."""
    for line in (Path(run_dir) / "journal.jsonl").read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        kind, when = event["type"], event["time"]
        if kind in ("reference", "measured") and event.get("measurement"):
            m = event["measurement"]
            who = "start" if kind == "reference" else event["candidate_id"][:8]
            gates = ""
            if kind == "measured":
                gates = "  ELIGIBLE" if not event["gates"] else "  gates: " + "; ".join(event["gates"])
            yield (
                f"{when}  {who:<8}  {m['right']}/{m['pairs']} pairs right  findings {m['findings']}  "
                f"{m['seconds'] / 3600:.2f} h{gates}"
            )
        elif kind == "measured":
            yield f"{when}  {event['candidate_id'][:8]}  failed: {event.get('failure')}"
        elif kind == "candidate":
            yield (
                f"{when}  turn {event['turn']}: {event['candidate_id'][:8]} from {event['parent_id'][:8]}: "
                f"{event['rationale'][:200]}"
            )
        elif kind == "turn" and not event.get("submitted"):
            why = event.get("finish_reason") or event.get("error") or "nothing submitted"
            yield f"{when}  turn {event['turn']}: no candidate ({why})"
        elif kind == "stop":
            yield f"{when}  stop: {event['reason']}"
        elif kind == "decision":
            yield f"{when}  best on the training pairs: {event['decision']['best_directory']}"
