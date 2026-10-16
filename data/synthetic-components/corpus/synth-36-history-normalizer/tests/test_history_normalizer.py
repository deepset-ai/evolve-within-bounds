from haystack_integrations.components.history_normalizer import HistoryNormalizer
from haystack_integrations.components.history_normalizer.history_normalizer_component import (
    resolve_role,
)


def test_server_transcript_decides():
    assert resolve_role({"index": 1}, server_roles={1: "assistant"}) == "assistant"
