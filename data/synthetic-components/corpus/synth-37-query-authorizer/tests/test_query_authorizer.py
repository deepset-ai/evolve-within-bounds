import pytest

from haystack_integrations.components.query_authorizer import QueryAuthorizer
from haystack_integrations.components.query_authorizer.query_authorizer_component import (
    Unauthorized,
    authorize,
)


def test_all_scopes_granted():
    assert authorize({"a", "b"}, {"a", "b", "c"}) == {"a", "b"}
def test_component_passes_through():
    out = QueryAuthorizer().run(scopes=["reports"], granted=["reports", "public"])
    assert out["scopes"] == ["reports"]
