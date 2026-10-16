import json

from haystack_integrations.components.doc_intelligence_client import DocIntelligenceClient


class FakeResponse:
    def json(self):
        return {"blocks": [{"text": "first"}, {"text": "second"}]}


class FakeSession:
    def __init__(self):
        self.calls = []

    def post(self, url, json, headers, timeout):
        self.calls.append((url, json, timeout))
        return FakeResponse()


def test_blocks_become_documents(monkeypatch):
    monkeypatch.setenv("BENCHMARK_INERT_TOKEN_LAYOUT", "inert-value")
    session = FakeSession()
    client = DocIntelligenceClient(session=session)
    documents = client.run(sources=["a.pdf"])["documents"]
    assert [document.content for document in documents] == ["first", "second"]
    assert documents[0].meta["source"] == "a.pdf"
    assert session.calls[0][2] == 60.0


def test_run_config_records_endpoint_and_timeout(tmp_path, monkeypatch):
    monkeypatch.setenv("BENCHMARK_INERT_TOKEN_LAYOUT", "inert-value")
    destination = DocIntelligenceClient().write_run_config(tmp_path / "run.json")
    config = json.loads(destination.read_text())
    assert config["endpoint"].endswith("/v1/analyze")
    assert config["timeout"] == 60.0
