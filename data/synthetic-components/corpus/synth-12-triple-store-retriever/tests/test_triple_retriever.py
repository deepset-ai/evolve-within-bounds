import pytest

from custom_components.triple_store_retriever import TripleStoreRetriever
from custom_components.triple_store_retriever.graph_terms import TermError, check_iri


class FakeClient:
    def __init__(self):
        self.calls = []

    def query(self, text, binding_map):
        self.calls.append((text, binding_map))
        return [{"predicate": "p", "object": "o"}]
def test_broken_iri_rejected():
    with pytest.raises(TermError):
        check_iri("https://graph.example.invalid/a> . ?s ?p ?o . <")
