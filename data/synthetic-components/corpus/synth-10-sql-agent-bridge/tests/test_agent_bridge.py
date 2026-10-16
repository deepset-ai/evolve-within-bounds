import sqlite3

import pytest

from custom_components.sql_agent_bridge import SqlAgentBridge
from custom_components.sql_agent_bridge.agent_bridge import BridgeRejected


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE orders (id TEXT, total INTEGER, status TEXT)")
    conn.execute("INSERT INTO orders VALUES ('42', 99, 'open')")
    return conn


def test_supported_lookup(connection):
    bridge = SqlAgentBridge(connection=connection)
    assert bridge.run(lookup="order_total", identifier="42")["rows"] == [(99,)]


def test_unsupported_lookup(connection):
    with pytest.raises(BridgeRejected):
        SqlAgentBridge(connection=connection).run(lookup="drop", identifier="x")
