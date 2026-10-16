import pytest

from haystack_integrations.components.websearch_bridge import WebSearchBridge
from haystack_integrations.components.websearch_bridge.websearch_bridge_component import SearchError


def test_empty_query_rejected():
    with pytest.raises(SearchError):
        WebSearchBridge()._check_query("   ")


def test_long_query_rejected():
    with pytest.raises(SearchError):
        WebSearchBridge()._check_query("x" * 600)


def test_secret_stays_a_reference(monkeypatch):
    monkeypatch.setenv("BENCHMARK_INERT_TOKEN_WEBSEARCH", "inert-value")
    assert "inert-value" not in repr(WebSearchBridge().to_dict())
