# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Decide which model-produced metadata keys may be written."""

from __future__ import annotations

from typing import Any

WRITABLE_KEYS = frozenset(
    {"summary", "topics", "language", "sentiment", "reading_time_minutes"}
)
PROTECTED_PREFIXES = ("acl", "tenant", "source", "_")


class MergeRejected(ValueError):
    """Raised when a merge would write outside the writable surface."""


def writable_subset(candidate: dict[str, Any]) -> dict[str, Any]:
    """Return only the keys a model is allowed to contribute.

    Model output is untrusted input. Without an allow-list a generated key such
    as `acl-groups` would silently overwrite the access control the retriever
    filters on.
    """
    return dict(candidate)
