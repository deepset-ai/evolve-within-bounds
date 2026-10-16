from haystack_integrations.components.usage_meter import UsageMeter


def test_payload_carries_token_counts(monkeypatch):
    monkeypatch.setenv("BENCHMARK_INERT_TOKEN_METERING", "inert-value")
    request = UsageMeter()._request({"run_id": "r-1", "prompt_tokens": 12, "completion_tokens": 3})
    assert b'"prompt_tokens": 12' in request.data
    assert request.get_method() == "POST"


def test_defaults():
    meter = UsageMeter()
    assert meter.endpoint.endswith("/v1/usage")
    assert meter.timeout == 10.0
