# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import inspect
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import openai
import pytest
from fake_vllm import FakeVllm
from haystack.dataclasses import ChatMessage
from helpers import model

import security_agent.generator as gen
from security_agent.generator import EMPTY_ANSWER, Generator, make_generator, thinking_kwargs, tolerate_empty_answers

REQUEST = httpx.Request("POST", "http://127.0.0.1:8000/v1/chat/completions")


def test_thinking_kwargs():
    assert thinking_kwargs(None) == {"extra_body": {"chat_template_kwargs": {"enable_thinking": False}}}
    assert thinking_kwargs(512) == {"extra_body": {"thinking_token_budget": 512}}


def test_generator_keeps_reasoning_and_sends_thinking_controls():
    with FakeVllm() as server:
        reply = make_generator(model(server.base_url), max_tokens=128, thinking_budget=300).run(
            [ChatMessage.from_user("How many prime numbers are there below 500?")]
        )["replies"][0]
        assert reply.text == "95" and reply.reasoning.reasoning_text.startswith("count")
        request = server.requests[-1]
        assert (
            request["thinking_token_budget"] == 300 and request["max_tokens"] == 128 and request["temperature"] == 0.0
        )

        reply = make_generator(model(server.base_url), max_tokens=16, thinking_budget=None).run(
            [ChatMessage.from_user("Reply with exactly the word OK and nothing else.")]
        )["replies"][0]
        assert reply.text == "OK" and reply.reasoning is None
        assert server.requests[-1]["chat_template_kwargs"] == {"enable_thinking": False}


def test_extra_kwargs_merge_into_extra_body():
    with FakeVllm() as server:
        make_generator(
            model(server.base_url),
            max_tokens=16,
            thinking_budget=64,
            extra={"extra_body": {"top_k": 20}, "top_p": 0.95},
        ).run([ChatMessage.from_user("Reply with exactly the word OK and nothing else.")])
        request = server.requests[-1]
        assert request["thinking_token_budget"] == 64 and request["top_k"] == 20 and request["top_p"] == 0.95


def test_greedy_with_thinking_budget_forces_temperature_zero():
    plain = model("http://127.0.0.1:9/v1")
    greedy = {**plain, "greedy_with_thinking_budget": True}

    def temperature(config, **kwargs):
        return make_generator(config, max_tokens=64, **kwargs).generation_kwargs["temperature"]

    assert temperature(greedy, thinking_budget=32, temperature=0.6) == 0.0
    assert temperature(greedy, thinking_budget=32, extra={"temperature": 0.7}) == 0.0
    assert temperature(greedy, thinking_budget=None, temperature=0.6) == 0.6  # no budget, no bug
    assert temperature(plain, thinking_budget=32, temperature=0.6) == 0.6


def test_empty_answers_are_asked_again_then_end_the_loop():
    attempts = []

    def run(messages, tools=None):  # noqa: ARG001 - the generator's signature
        attempts.append(messages)
        raise ValueError("A `ChatMessage` must contain at least one `TextContent`, `ToolCall`, ...")

    out = tolerate_empty_answers(run)(["m"])
    assert len(attempts) == 2 and out["replies"][0].text == EMPTY_ANSWER
    assert "tools" in inspect.signature(tolerate_empty_answers(run)).parameters  # the Agent still sees `tools`

    def other(messages, tools=None):  # noqa: ARG001
        raise ValueError("other")

    with pytest.raises(ValueError, match="other"):
        tolerate_empty_answers(other)(["m"])


def test_generator_logs_every_call():
    with FakeVllm() as server:
        generator = Generator(model(server.base_url), max_tokens=64, thinking_budget=None)
        generator.run([ChatMessage.from_user("Reply with exactly the word OK and nothing else.")])
    call = generator.calls[-1]
    assert call["prompt_tokens"] == 50 and call["completion_tokens"] == 20 and call["finish_reason"] == "stop"
    assert [m.role.value for m in generator.transcript] == ["user", "assistant"]


# -- model-server outages ------------------------------------------------------------------------


def _status(code):
    cls = openai.InternalServerError if code >= 500 else openai.BadRequestError
    return cls("boom", response=httpx.Response(code, request=REQUEST), body=None)


def test_server_down_recognises_outages_only():
    assert gen.server_down(_status(502)) and gen.server_down(_status(503))
    assert gen.server_down(openai.APIConnectionError(request=REQUEST))
    assert not gen.server_down(_status(400)) and not gen.server_down(ValueError("bad json"))
    try:
        try:
            raise _status(502)  # noqa: TRY301 - the error Haystack wraps
        except Exception as inner:
            raise RuntimeError("agent failed") from inner  # Haystack may wrap the client's error
    except RuntimeError as wrapped:
        assert gen.server_down(wrapped)
    assert gen.server_error_text("InternalServerError: <html><head><title>502 Bad Gateway</title>")
    assert not gen.server_error_text("JSONDecodeError: Expecting value") and not gen.server_error_text(None)


def test_call_waiting_waits_out_an_outage_and_retries(monkeypatch):
    waits = []
    monkeypatch.setattr(gen, "wait_for_server", lambda url, model, **kw: waits.append(url) or True)
    calls = iter([_status(502), openai.APIConnectionError(request=REQUEST), "answer"])

    def call():
        item = next(calls)
        if isinstance(item, Exception):
            raise item
        return item

    seen = []
    assert gen.call_waiting(call, "http://x/v1", "m", on_wait=lambda: seen.append(1)) == "answer"
    assert waits == ["http://x/v1", "http://x/v1"] and seen == [1, 1]
    with pytest.raises(openai.BadRequestError):  # a model or request error is not waited out
        gen.call_waiting(lambda: (_ for _ in ()).throw(_status(400)), "http://x/v1", "m")
    monkeypatch.setattr(gen, "wait_for_server", lambda url, model, **kw: False)
    with pytest.raises(openai.InternalServerError):  # the server never came back
        gen.call_waiting(lambda: (_ for _ in ()).throw(_status(502)), "http://x/v1", "m")


def test_a_server_answers_only_with_a_real_completion():
    assert gen.wait_for_server("http://127.0.0.1:9/v1", "m", limit_s=0.3, poll_s=0.1) is False

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert body["max_tokens"] == 1 and body["chat_template_kwargs"] == {"enable_thinking": False}
            payload = json.dumps({"choices": [{"message": {"content": "OK"}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert gen.server_answers(f"http://127.0.0.1:{server.server_port}/v1", "m")
    finally:
        server.shutdown()
