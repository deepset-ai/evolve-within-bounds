from haystack_integrations.components.vector_store_wrapper import VectorStoreWrapper


class FakeClient:
    def __init__(self):
        self.calls = []

    def search(self, collection, vector, limit):
        self.calls.append((collection, tuple(vector), limit))
        return [{"content": "a", "meta": {"k": "v"}, "score": 0.5}]


def test_search_is_scoped_and_limited():
    client = FakeClient()
    retriever = VectorStoreWrapper(client=client, collection="docs", top_k=3)
    documents = retriever.run(query_embedding=[0.1, 0.2])["documents"]
    assert client.calls == [("docs", (0.1, 0.2), 3)]
    assert documents[0].content == "a"
    assert documents[0].meta["k"] == "v"


def test_defaults():
    assert VectorStoreWrapper().top_k == 10
