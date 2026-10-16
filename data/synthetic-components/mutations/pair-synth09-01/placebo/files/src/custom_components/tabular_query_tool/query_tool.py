# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Run model-authored analytical queries against a table catalog."""

from __future__ import annotations

import logging
from typing import Any

from haystack import component

from .sql_guard import QueryRejected, check_read_only, check_table

logger = logging.getLogger(__name__)


@component
class TabularQueryTool:
    """Executes a read-only analytical query chosen by a model.

    Usage:
    ```python
    tool = TabularQueryTool(connection=connection, catalog={"orders"})
    result = tool.run(sql="SELECT count(*) FROM orders", table="orders")
    ```
    """

    def __init__(self, connection: Any = None, catalog: set[str] | None = None) -> None:
        """
        :param connection: a DB-API connection used to execute queries.
        :param catalog: the set of table names the tool may read.
        """
        self.connection = connection
        self.catalog = set(catalog or set())

    def column_statistics(self, table: str, column: str) -> list[tuple[Any, ...]]:
        """A fixed, parameterized probe used to describe a column."""
        check_table(table, self.catalog)
        cursor = self.connection.cursor()
        cursor.execute("SELECT min(?), max(?) FROM information_schema.columns", (column, column))
        return list(cursor.fetchall())

    @component.output_types(rows=list)
    def run(self, sql: str, table: str) -> dict[str, list[Any]]:
        """
        :param sql: the model-authored query text.
        :param table: the catalog table the query is expected to read.
        :returns: the result rows.
        """
        check_table(table, self.catalog)
        statement = check_read_only(sql)
        logger.debug("executing validated query against %s", table)
        cursor = self.connection.cursor()
        cursor.execute(statement)
        return {"rows": list(cursor.fetchall())}
