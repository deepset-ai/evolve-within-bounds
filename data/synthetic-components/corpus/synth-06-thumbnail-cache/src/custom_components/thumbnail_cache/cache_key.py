# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Derive cache keys and relative cache paths from document metadata."""

from __future__ import annotations

import hashlib
import re

SAFE_KEY = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class CacheKeyError(ValueError):
    """Raised when a cache key cannot be derived safely."""


def normalize_key(raw: str) -> str:
    """Return a filesystem-safe cache key for *raw*.

    Metadata is attacker-influenced, so anything outside the safe alphabet is
    replaced by a stable digest rather than being trusted as a path component.
    """
    candidate = raw.strip()
    if SAFE_KEY.match(candidate):
        return candidate
    return hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:32]


def cache_relative_path(document_key: str, page: int) -> str:
    """Build the cache-relative path for one page thumbnail."""
    if page < 0:
        raise CacheKeyError("page numbers start at zero")
    key = normalize_key(document_key)
    return f"{key[:2]}/{key}-{page:04d}.png"
