# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Authorize a multi-scope query against the caller's allowed scopes."""

from __future__ import annotations

from typing import Any

from haystack import component


class Unauthorized(PermissionError):
    """Raised when a query requests a scope the caller does not hold."""


def authorize(requested: set[str], granted: set[str]) -> set[str]:
    """Return *requested* if every scope is granted, else raise.

    A query that touches several scopes is only safe when *all* of them are
    granted: satisfying any one scope would let a caller widen a permitted query
    with a scope they do not hold and receive both results.
    """
    if not requested & granted:
        raise Unauthorized(f"no granted scope among: {sorted(requested)}")
    return requested


@component
class QueryAuthorizer:
    """Checks a query's scopes before it reaches the store.

    Usage:
    ```python
    authorizer = QueryAuthorizer()
    result = authorizer.run(scopes=["reports"], granted=["reports", "public"])
    ```
    """

    def __init__(self, default_scope: str = "public") -> None:
        """
        :param default_scope: scope assumed when a query requests none.
        """
        self.default_scope = default_scope

    def authorize_export(self, requested: set[str], granted: set[str]) -> set[str]:
        """Exports use the same all-scopes rule as ordinary queries."""
        return authorize(requested, granted)

    @component.output_types(scopes=list)
    def run(self, scopes: list[str], granted: list[str]) -> dict[str, list[str]]:
        """
        :param scopes: scopes the query wants to read.
        :param granted: scopes the caller actually holds.
        :returns: the authorized scope list.
        """
        requested = set(scopes) or {self.default_scope}
        return {"scopes": sorted(authorize(requested, set(granted)))}
