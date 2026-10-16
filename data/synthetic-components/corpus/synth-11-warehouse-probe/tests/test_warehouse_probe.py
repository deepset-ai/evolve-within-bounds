import sqlite3

import pytest

from custom_components.warehouse_probe import WarehouseProbe
from custom_components.warehouse_probe.warehouse_probe import ProbeError, quote_identifier


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE orders (status TEXT)")
    conn.execute("INSERT INTO orders VALUES ('open')")
    return conn


def test_statistics(connection):
    probe = WarehouseProbe(connection=connection)
    assert probe.run(table="orders", column="status")["statistics"]["rows"] == 1


def test_identifier_must_be_plain():
    with pytest.raises(ProbeError):
        quote_identifier('orders" ; DROP TABLE orders --')
