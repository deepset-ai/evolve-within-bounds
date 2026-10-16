import sqlite3

import pytest

from custom_components.tabular_query_tool import TabularQueryTool
from custom_components.tabular_query_tool.sql_guard import QueryRejected, check_read_only


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE orders (id INTEGER)")
    conn.execute("INSERT INTO orders VALUES (1)")
    return conn


def test_select_is_allowed(connection):
    tool = TabularQueryTool(connection=connection, catalog={"orders"})
    assert tool.run(sql="SELECT count(*) FROM orders", table="orders")["rows"] == [(1,)]
def test_unknown_table_rejected(connection):
    tool = TabularQueryTool(connection=connection, catalog={"orders"})
    with pytest.raises(QueryRejected):
        tool.run(sql="SELECT 1", table="secrets")
