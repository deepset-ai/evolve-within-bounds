# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from security_agent.serving import smoke


def _tool_call(name, arguments):
    return {"id": f"call-{name}", "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}


def fake_completion(body, reasoning_factor):
    """Answer like a well-behaved vLLM server, scaling the reasoning tokens against the budget by `reasoning_factor`."""
    tools = [tool["function"]["name"] for tool in body.get("tools", [])]
    if "record_note" in tools:
        note = body["messages"][-1]["content"].split("\n\n", 1)[1]
        return {"content": "", "tool_calls": [_tool_call("record_note", {"note": note})]}, "tool_calls", {}
    if "submit_finding" in tools:
        if any(message["role"] == "tool" for message in body["messages"]):
            finding = {"path": "src/sample/store.py", "line": 12, "cwe": "CWE-89"}
            return {"content": "", "tool_calls": [_tool_call("submit_finding", finding)]}, "tool_calls", {}
        return (
            {"content": "", "tool_calls": [_tool_call("read_file", {"path": "src/sample/store.py"})]},
            "tool_calls",
            {},
        )
    if "response_format" in body:
        candidate = {
            "path": "src/users.py",
            "line_start": 4,
            "line_end": 5,
            "cwe": "CWE-89",
            "title": "SQLi",
            "confidence": 90,
        }
        return {"content": json.dumps({"candidates": [candidate]}), "reasoning": "x"}, "stop", {"completion_tokens": 40}
    if "thinking_token_budget" in body:
        tokens = int(body["thinking_token_budget"] * reasoning_factor)
        usage = {"completion_tokens": tokens + 2, "completion_tokens_details": {"reasoning_tokens": tokens}}
        return {"content": "62", "reasoning": "2, 3, 5, 7, ..."}, "stop", usage
    return {"content": "OK"}, "stop", {"completion_tokens": 12}


def serve(reasoning_factor):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, payload):
            data = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._send({"data": [{"id": "fake-model"}]})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            message, finish_reason, usage = fake_completion(body, reasoning_factor)
            self._send({"choices": [{"message": message, "finish_reason": finish_reason}], "usage": usage})

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def base_url(request):
    server = serve(getattr(request, "param", 0.98))
    yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    server.shutdown()


def test_every_check_passes_against_a_well_behaved_server(base_url, tmp_path):
    report = tmp_path / "smoke.json"
    assert smoke.main(["--base-url", base_url, "--report", str(report)]) == 0
    data = json.loads(report.read_text())
    assert data["model"] == "fake-model"
    assert data["passed"] is True
    assert [check["name"] for check in data["checks"]] == [
        "reasoning_surfaced",
        "thinking_budget_honored",
        "chat_basic",
        "guided_json",
        "guided_json_tight_budget",
        "long_tool_argument",
        "tool_loop",
        "concurrency",
    ]
    tool_loop = next(check for check in data["checks"] if check["name"] == "tool_loop")
    assert tool_loop["details"]["tool_calls"] == ["read_file", "submit_finding"]
    assert tool_loop["details"]["located_correctly"] is True


@pytest.mark.parametrize("base_url", [3.0, 0.2], indirect=True, ids=["budget-ignored", "budget-not-binding"])
def test_thinking_budget_fails_when_the_cap_does_not_bind_or_hold(base_url, tmp_path):
    report = tmp_path / "smoke.json"
    assert smoke.main(["--base-url", base_url, "--report", str(report)]) == 1
    failed = [check["name"] for check in json.loads(report.read_text())["checks"] if not check["passed"]]
    assert failed == ["thinking_budget_honored"]


def test_malformed_tool_calls_are_detected():
    no_call = smoke.Reply(content="", reasoning="", tool_calls=[], finish_reason="tool_calls", usage={})
    bad_json = smoke.Reply(
        content="",
        reasoning="",
        tool_calls=[{"function": {"name": "f", "arguments": "{not json"}}],
        finish_reason="tool_calls",
        usage={},
    )
    good = smoke.Reply(
        content="", reasoning="", tool_calls=[_tool_call("f", {"a": 1})], finish_reason="tool_calls", usage={}
    )
    assert no_call.malformed_tool_calls()
    assert bad_json.malformed_tool_calls()
    assert not good.malformed_tool_calls()


def test_reasoning_tokens_fall_back_to_an_estimate():
    reported = smoke.Reply("", "x" * 35, [], "stop", {"completion_tokens_details": {"reasoning_tokens": 7}})
    estimated = smoke.Reply("", "x" * 35, [], "stop", {})
    assert reported.reasoning_tokens() == (7, "usage")
    assert estimated.reasoning_tokens() == (10, "estimate")


def test_a_server_listing_several_models_needs_an_explicit_model(monkeypatch, capsys):
    monkeypatch.setattr(smoke, "served_models", lambda base_url: ["a", "b"])
    assert smoke.main(["--base-url", "http://127.0.0.1:9/v1"]) == 1
    assert "pass --model" in capsys.readouterr().err
