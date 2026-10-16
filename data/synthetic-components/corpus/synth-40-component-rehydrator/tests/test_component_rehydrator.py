import pytest

from haystack_integrations.components.component_rehydrator import ComponentRehydrator
from haystack_integrations.components.component_rehydrator.component_rehydrator_component import (
    RehydrationError,
    build_stage,
)


def test_registered_stage():
    stage = build_stage({"type": "truncate", "init_parameters": {"limit": 3}})
    assert stage.apply("abcdef") == "abc"
def test_chain_length_bounded():
    with pytest.raises(RehydrationError):
        ComponentRehydrator(max_stages=1).run(
            state=[{"type": "passthrough"}, {"type": "passthrough"}]
        )
