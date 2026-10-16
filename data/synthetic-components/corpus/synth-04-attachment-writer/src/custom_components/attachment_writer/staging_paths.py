# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Resolve staging paths for extracted attachments."""

from __future__ import annotations

from pathlib import Path


class StagingError(ValueError):
    """Raised when a resolved path would escape the staging root."""


def contained_path(root: Path, relative: str) -> Path:
    """Resolve *relative* under *root* and prove the result stays inside it."""
    candidate = (root / relative).resolve()
    resolved_root = root.resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise StagingError(f"path escapes the staging root: {relative!r}")
    return candidate


def temp_path(root: Path, run_id: str) -> Path:
    """A scratch path for one run, built through the same containment check."""
    return contained_path(root, f".tmp/{run_id}.part")
