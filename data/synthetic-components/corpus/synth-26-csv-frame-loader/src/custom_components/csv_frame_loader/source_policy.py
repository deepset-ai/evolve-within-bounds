# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Decide what a frame loader is allowed to read."""

from __future__ import annotations

from pathlib import Path


class SourceRejected(ValueError):
    """Raised when a frame source is not a local file under the data root."""


def local_source(data_root: Path, reference: str) -> Path:
    """Resolve *reference* to a local path under *data_root*.

    Frame libraries treat a string that looks like a URL as something to fetch,
    so a reference is resolved to a real path here and never handed over as text.
    """
    if "://" in reference:
        raise SourceRejected(f"remote sources are not supported: {reference!r}")
    candidate = (data_root / reference).resolve()
    root = data_root.resolve()
    if root not in candidate.parents and candidate != root:
        raise SourceRejected(f"source escapes the data root: {reference!r}")
    if not candidate.is_file():
        raise SourceRejected(f"source is not a file: {reference!r}")
    return candidate
