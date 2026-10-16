import pytest

from custom_components.routing_expression import RoutingExpression
from custom_components.routing_expression.routing_expression import ConditionError, evaluate


def test_numeric_comparison():
    assert evaluate("length > 100", {"length": 250}) is True


def test_string_comparison():
    assert evaluate("lang == 'en'", {"lang": "en"}) is True


def test_unknown_field():
    with pytest.raises(ConditionError):
        evaluate("other == 1", {"length": 1})


def test_router_picks_branch():
    router = RoutingExpression(routes={"long": "length > 100"})
    assert router.run(scope={"length": 250})["branch"] == "long"
