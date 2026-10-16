from haystack.dataclasses import ChatMessage

from haystack_integrations.components.chat_relay import ChatRelay


class FakeResponse:
    def json(self):
        return {"choices": [{"message": {"content": "hello back"}}]}


class FakeSession:
    def __init__(self):
        self.calls = []

    def post(self, url, json, headers, timeout):
        self.calls.append((url, json, timeout))
        return FakeResponse()


def test_reply_is_returned(monkeypatch):
    monkeypatch.setenv("BENCHMARK_INERT_TOKEN_CHAT", "inert-value")
    session = FakeSession()
    relay = ChatRelay(session=session)
    replies = relay.run(messages=[ChatMessage.from_user("hello")])["replies"]
    assert replies[0].text == "hello back"
    assert session.calls[0][2] == 45.0


def test_state_reports_endpoint_and_model(monkeypatch):
    monkeypatch.setenv("BENCHMARK_INERT_TOKEN_CHAT", "inert-value")
    state = ChatRelay().describe_state()
    assert state["model"] == "example-chat-small"
    assert state["endpoint"].endswith("/v1/completions")
