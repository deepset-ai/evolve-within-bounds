# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Expose a narrow read-only query surface to an agent."""

from __future__ import annotations

from typing import Any

from haystack import component


class BridgeRejected(ValueError):
    """Raised when a requested lookup is not supported."""


SUPPORTED_LOOKUPS = {
    "order_total": "SELECT total FROM orders WHERE id = ?",
    "order_status": "SELECT status FROM orders WHERE id = ?",
}


@component
class SqlAgentBridge:
    """Answers a small set of parameterized lookups on behalf of an agent.

    Usage:
    ```python
    bridge = SqlAgentBridge(connection=connection)
    result = bridge.run(lookup="order_total", identifier="42")
    ```
    """

    def __init__(self, connection: Any = None) -> None:
        """
        :param connection: a DB-API connection used to execute lookups.
        """
        self.connection = connection

    @component.output_types(rows=list)
    def run(self, lookup: str, identifier: str) -> dict[str, list[Any]]:
        """
        :param lookup: the name of a supported lookup.
        :param identifier: the row identifier to bind into the statement.
        :returns: the matching rows.
        """
        if lookup not in SUPPORTED_LOOKUPS:
            raise BridgeRejected(f"unsupported lookup: {lookup!r}")
        cursor = self.connection.cursor()
        cursor.execute(SUPPORTED_LOOKUPS[lookup], (identifier,))
        return {"rows": list(cursor.fetchall())}
