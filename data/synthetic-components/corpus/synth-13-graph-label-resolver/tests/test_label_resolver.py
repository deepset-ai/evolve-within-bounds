import pytest

from custom_components.graph_label_resolver import GraphLabelResolver
from custom_components.graph_label_resolver.label_resolver import LabelError, check_node_id


class FakeClient:
    def __init__(self):
        self.calls = []

    def query(self, text, binding_map):
        self.calls.append((text, binding_map))
        return [{"label": "Alpha"}]


def test_labels_resolved():
    resolver = GraphLabelResolver(client=FakeClient())
    assert resolver.run(node_ids=["ex:alpha"])["labels"]["ex:alpha"] == "Alpha"
def test_bad_identifier_rejected():
    with pytest.raises(LabelError):
        check_node_id("ex:a } UNION { ?s ?p ?o")
