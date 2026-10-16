# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Sample column statistics to support schema-aware retrieval."""

from __future__ import annotations

import re
from typing import Any

from haystack import component

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class ProbeError(ValueError):
    """Raised when an identifier is not a plain column or table name."""


def quote_identifier(name: str) -> str:
    """Validate and quote a SQL identifier.

    Identifiers cannot be bound as parameters, so they are checked against a
    strict pattern and then quoted, never interpolated raw.
    """
    if not IDENTIFIER.match(name):
        raise ProbeError(f"not a plain identifier: {name!r}")
    return '"' + name + '"'


@component
class WarehouseProbe:
    """Reports row counts and distinct-value counts for a column.

    Usage:
    ```python
    probe = WarehouseProbe(connection=connection)
    result = probe.run(table="orders", column="status")
    ```
    """

    def __init__(self, connection: Any = None, sample_limit: int = 1000) -> None:
        """
        :param connection: a DB-API connection.
        :param sample_limit: how many rows to sample.
        """
        self.connection = connection
        self.sample_limit = sample_limit

    @component.output_types(statistics=dict)
    def run(self, table: str, column: str) -> dict[str, dict[str, Any]]:
        """
        :param table: the table to sample.
        :param column: the column to describe.
        :returns: row and distinct counts for the column.
        """
        safe_table = quote_identifier(table)
        safe_column = quote_identifier(column)
        cursor = self.connection.cursor()
        cursor.execute(
            f"SELECT count(*), count(DISTINCT {safe_column}) FROM {safe_table} LIMIT ?",
            (self.sample_limit,),
        )
        rows, distinct = cursor.fetchone()
        return {"statistics": {"rows": rows, "distinct": distinct}}
