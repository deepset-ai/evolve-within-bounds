# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Candidates: identity, files and diffs. What a valid candidate is depends on the task.

- `candidate_id`: identity by content. YAML files count as parsed YAML, and the other files with trailing whitespace
  stripped, so a comment or a reformatting is not a new candidate.
- `diff`: a unified diff between two candidate directories, for the journal and the optimizer's outcomes.
- `added_text`: the lines a diff adds, which is where a candidate could copy training answers (the leakage check).
"""

from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path

import yaml


def files(directory: Path) -> list[str]:
    """A candidate's files, relative to it."""
    return sorted(
        p.relative_to(directory).as_posix()
        for p in Path(directory).rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    )


def candidate_id(directory: Path) -> str:
    """The candidate's content id. Never raises: YAML that does not parse counts by its raw text."""
    directory = Path(directory)
    payload = {}
    for rel in files(directory):
        text = (directory / rel).read_text(encoding="utf-8")
        try:
            if rel.endswith((".yaml", ".yml")):
                payload[rel] = yaml.safe_load(text)
            else:
                payload[rel] = "\n".join(line.rstrip() for line in text.splitlines()).rstrip()
        except yaml.YAMLError:
            payload[rel] = {"unparseable": text}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:16]


def diff(parent: Path, child: Path, context: int = 2) -> str:
    """A unified diff from one candidate directory to another."""
    out: list[str] = []
    for rel in sorted(set(files(parent)) | set(files(child))):
        a = (parent / rel).read_text(encoding="utf-8").splitlines(True) if (parent / rel).is_file() else []
        b = (child / rel).read_text(encoding="utf-8").splitlines(True) if (child / rel).is_file() else []
        out += difflib.unified_diff(a, b, f"parent/{rel}", f"candidate/{rel}", n=context)
    return "".join(out)


def added_text(diff_text: str) -> str:
    """The lines a diff adds: the only place a candidate can introduce leaked material."""
    return "\n".join(line[1:] for line in diff_text.splitlines() if line.startswith("+") and not line.startswith("+++"))
