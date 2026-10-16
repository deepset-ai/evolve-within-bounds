import pytest

from custom_components.odata_filter_bridge import ODataFilterBridge
from custom_components.odata_filter_bridge.odata_bridge import BridgeError


def test_expression_shape():
    bridge = ODataFilterBridge()
    result = bridge.run(field="collection_id", value="reports")
    assert result["filter"] == "meta/collection_id eq 'reports' and meta/state eq 'indexed'"
def test_bad_field_rejected():
    with pytest.raises(BridgeError):
        ODataFilterBridge().run(field="a/b", value="x")
