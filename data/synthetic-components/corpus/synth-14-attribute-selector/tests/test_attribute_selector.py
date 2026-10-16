import pytest

from custom_components.attribute_selector import AttributeSelector
from custom_components.attribute_selector.attribute_selector import SelectorError, resolve


def test_nested_lookup():
    assert resolve({"meta": {"lang": "en"}}, "meta.lang") == "en"


def test_missing_key_is_none():
    assert resolve({"meta": {}}, "meta.lang") is None
def test_component_projects():
    out = AttributeSelector(selectors=["meta.lang"]).run(payloads=[{"meta": {"lang": "de"}}])
    assert out["values"][0]["meta.lang"] == "de"
