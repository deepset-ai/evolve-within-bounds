# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Model calls to the local vLLM (or NIM) server, configured from `config/model*.yaml`.

- `make_generator`: Haystack's `VLLMChatGenerator` with the request settings the scanner needs: a per-request
  thinking budget (or thinking off), temperature and output limit. It keeps the model's reasoning as
  `ChatMessage.reasoning`.
- `Generator`: the same, as a chat generator for Haystack's `Agent` and for direct calls. It logs every call (tokens,
  seconds, finish reason), keeps the last conversation, and waits out a model-server outage. Time lost waiting is
  recorded per call (`lost_s`), so it does not count against an agent's time limit.
- **Outages.** A server that crashes or restarts answers every request with an error for a few minutes. A call that
  fails that way waits until the server generates again (one-token probes) and is retried, up to `MAX_SERVER_WAITS`
  times of at most `SERVER_WAIT_S` each. Any other error is the caller's to handle.
"""

from __future__ import annotations

import functools
import json
import re
import threading
import time
import urllib.request
from collections.abc import Callable
from typing import Any

import openai
from haystack.dataclasses import ChatMessage, ReasoningContent
from haystack_integrations.components.generators.vllm import VLLMChatGenerator

SERVER_DOWN_STATUS = {502, 503, 504}
MAX_SERVER_WAITS = 3
SERVER_WAIT_S = 1800
THINK = re.compile(r"^\s*<think>(.*?)</think>\s*", re.DOTALL)
SERVER_ERROR_TEXT = re.compile(
    r"^(InternalServerError|APIConnectionError|APITimeoutError|ServiceUnavailableError)\b|502 Bad Gateway"
)


def server_down(error: BaseException) -> bool:
    """Is this (or what caused it) a model-server outage rather than an answer the model gave?"""
    seen = set()
    exc: BaseException | None = error
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, openai.APIConnectionError):  # refused, reset, or timed out (APITimeoutError)
            return True
        if isinstance(exc, openai.APIStatusError) and exc.status_code in SERVER_DOWN_STATUS:
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def server_error_text(text: str | None) -> bool:
    """Does a recorded error message (`Type: message`) describe a server outage?"""
    return bool(text and SERVER_ERROR_TEXT.search(text))


def server_answers(api_base_url: str, model: str, timeout_s: float = 60.0) -> bool:
    """
    Does the server generate? One output token, thinking off.

    `/v1/models` is no test: a server can answer it while its engine is still loading, or hung.
    """
    body = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": "Reply with OK."}],
            "max_tokens": 1,
            "chat_template_kwargs": {"enable_thinking": False},
        }
    ).encode()
    request = urllib.request.Request(
        api_base_url.rstrip("/") + "/chat/completions", data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:  # noqa: S310 - the local model server
            return response.status == 200 and bool(json.loads(response.read()).get("choices"))
    except Exception:  # noqa: BLE001 - down, loading or hung: not ready
        return False


def wait_for_server(api_base_url: str, model: str, limit_s: float = SERVER_WAIT_S, poll_s: float = 15.0) -> bool:
    """Wait until the server generates again (True), or give up after `limit_s` (False)."""
    deadline = time.monotonic() + limit_s
    while time.monotonic() < deadline:
        if server_answers(api_base_url, model):
            return True
        time.sleep(poll_s)
    return False


def call_waiting(
    call: Callable[[], Any], api_base_url: str, model: str, on_wait: Callable[[], None] | None = None
) -> Any:
    """`call()`, waiting out a model-server outage up to `MAX_SERVER_WAITS` times. Other errors propagate at once."""
    for waits in range(MAX_SERVER_WAITS + 1):
        try:
            return call()
        except Exception as exc:
            if not server_down(exc) or waits == MAX_SERVER_WAITS or not wait_for_server(api_base_url, model):
                raise
            if on_wait:
                on_wait()
    raise AssertionError("unreachable")


def thinking_kwargs(budget: int | None) -> dict[str, Any]:
    """
    Per-request thinking control: `None` turns thinking off, an int caps the reasoning tokens.

    Always pass one of the two: without a cap, Flash-Next can think for thousands of tokens and never answer, and the
    server gives no "budget reached" signal.
    """
    if budget is None:
        return {"extra_body": {"chat_template_kwargs": {"enable_thinking": False}}}
    return {"extra_body": {"thinking_token_budget": int(budget)}}


def as_gym_metadata(extra_body: dict[str, Any]) -> dict[str, str]:
    """
    vLLM's request options for a NeMo Gym model server, which accepts only OpenAI's request fields.

    Gym's vLLM model server reads them from `metadata` instead, as JSON strings, and merges them into the request it
    sends to vLLM: `chat_template_kwargs` under its own key, everything else (the thinking budget) under `extra_body`.
    """
    extra_body = dict(extra_body)
    metadata = {}
    if template := extra_body.pop("chat_template_kwargs", None):
        metadata["chat_template_kwargs"] = json.dumps(template)
    if extra_body:
        metadata["extra_body"] = json.dumps(extra_body)
    return metadata


def unwrap_reasoning(reply: ChatMessage) -> ChatMessage:
    """
    A NeMo Gym model server's reply as vLLM gives it.

    Gym's vLLM server returns chat completions with the model's reasoning wrapped in `<think>` tags at the start of the
    text; this puts it back in `reasoning`, so the agent and its records see the same reply in both setups.
    """
    match = THINK.match(reply.text or "")
    if match is None or reply.reasoning is not None:
        return reply
    return ChatMessage.from_assistant(
        text=(reply.text or "")[match.end() :] or None,
        tool_calls=reply.tool_calls,
        meta=reply.meta,
        reasoning=ReasoningContent(reasoning_text=match.group(1)),
    )


def malformed_tool_calls(reply: ChatMessage) -> bool:
    """
    Did the model try to call a tool with arguments that are not valid JSON?

    The generator drops such a call and only logs a warning. What remains visible is a reply whose finish reason is
    `tool_calls` but that carries no parsed call.
    """
    return (reply.meta or {}).get("finish_reason") == "tool_calls" and not reply.tool_calls


EMPTY_ANSWER = "(the model returned no answer)"


def empty_answer(error: BaseException) -> bool:
    """Is this the error Haystack raises when the model's reply holds only reasoning: no text and no tool call?"""
    return isinstance(error, ValueError) and "must contain at least one" in str(error)


def tolerate_empty_answers(run: Callable[..., dict], retries: int = 1) -> Callable[..., dict]:
    """
    `run`, asked again on an empty answer (`retries` times), then answering `EMPTY_ANSWER` instead of raising.

    Nemotron 3.5 Super VL sometimes replies with reasoning only. Without this, the error would end an agent's scan; with
    it, the agent's loop ends normally.
    """

    @functools.wraps(run)  # the Agent checks run's signature for `tools`
    def wrapped(*args: Any, **kwargs: Any) -> dict:
        for _ in range(retries + 1):
            try:
                return run(*args, **kwargs)
            except ValueError as exc:
                if not empty_answer(exc):
                    raise
        return {"replies": [ChatMessage.from_assistant(EMPTY_ANSWER, meta={"finish_reason": "empty"})]}

    return wrapped


def cached_tokens(usage: dict[str, Any]) -> int:
    """
    Prompt tokens the server took from its prefix cache, so did not compute again.

    vLLM reports them with --enable-prompt-tokens-details. An agent resends its whole conversation at every step, so
    most are cached.
    """
    return int(((usage or {}).get("prompt_tokens_details") or {}).get("cached_tokens") or 0)


def make_generator(
    model: dict[str, Any],
    *,
    max_tokens: int,
    thinking_budget: int | None,
    temperature: float | None = None,
    extra: dict[str, Any] | None = None,
) -> VLLMChatGenerator:
    """
    A generator for the model config. `thinking_budget=None` turns thinking off.

    With `gym_model_server: true` in the config, the server is a NeMo Gym model server in front of vLLM, and vLLM's
    request options travel as `metadata` (`as_gym_metadata`).
    """
    generation_kwargs: dict[str, Any] = {
        "max_tokens": int(max_tokens),
        "temperature": model.get("temperature", 0.0) if temperature is None else temperature,
        **thinking_kwargs(thinking_budget),
    }
    if extra:
        extra = dict(extra)
        merged_body = {**generation_kwargs["extra_body"], **extra.pop("extra_body", {})}
        generation_kwargs.update(extra)
        generation_kwargs["extra_body"] = merged_body
    if model.get("greedy_with_thinking_budget") and thinking_budget is not None:
        # A server bug (serving/nemotron-3.5-super-vl): with a thinking budget and a temperature above 0, everything
        # after the budget is lost, and the call generates nothing visible until max_tokens.
        generation_kwargs["temperature"] = 0.0
    if model.get("gym_model_server"):
        generation_kwargs["metadata"] = as_gym_metadata(generation_kwargs.pop("extra_body"))
    return VLLMChatGenerator(
        model=model["model"],
        api_base_url=model["api_base_url"],
        generation_kwargs=generation_kwargs,
        timeout=float(model.get("timeout_s", 600)),
        max_retries=int(model.get("max_retries", 3)),
    )


def run_waiting(generator: VLLMChatGenerator, messages: list[ChatMessage]) -> dict[str, Any]:
    """`generator.run(messages)`, waiting out a model-server outage."""
    return call_waiting(lambda: generator.run(messages), generator.api_base_url, generator.model)


class Generator:
    """
    A chat generator for Haystack's Agent and for direct calls, with `make_generator`'s settings.

    Every call is logged in `calls` (tokens, seconds, finish reason, and `lost_s`, the seconds spent waiting out an
    outage). `before_call` (optional) runs before each call; it may raise to stop the caller, e.g. when a per-scan
    budget is spent. `transcript` holds the last call's messages and reply: for an agent, its whole conversation.
    """

    def __init__(
        self,
        model: dict[str, Any],
        *,
        max_tokens: int,
        thinking_budget: int | None,
        temperature: float | None = None,
        extra: dict[str, Any] | None = None,
        before_call: Callable[[], None] | None = None,
    ) -> None:
        self.model = model
        self._generator = make_generator(
            model, max_tokens=max_tokens, thinking_budget=thinking_budget, temperature=temperature, extra=extra
        )
        self.before_call = before_call
        self.calls: list[dict[str, Any]] = []
        self.transcript: list[ChatMessage] = []
        self._lock = threading.Lock()

    def _attempts(self, call: Callable[[], dict[str, Any]]) -> tuple[dict[str, Any], float]:
        lost = 0.0
        for waits in range(MAX_SERVER_WAITS + 1):
            started = time.monotonic()
            try:
                return call(), lost
            except Exception as exc:
                if not server_down(exc) or waits == MAX_SERVER_WAITS:
                    raise
                if not wait_for_server(self.model["api_base_url"], self.model["model"]):
                    raise
                lost += time.monotonic() - started
        raise AssertionError("unreachable")

    def run(
        self,
        messages: list[ChatMessage],
        streaming_callback: Any = None,  # noqa: ARG002 - the chat generator interface; nothing streams
        generation_kwargs: dict[str, Any] | None = None,
        *,
        tools: Any = None,
    ) -> dict[str, list[ChatMessage]]:
        """Call the model, waiting out a model-server outage; logs the call."""
        if self.before_call:
            self.before_call()
        started = time.monotonic()
        try:
            out, lost = self._attempts(
                lambda: self._generator.run(messages=messages, generation_kwargs=generation_kwargs, tools=tools)
            )
        except Exception as exc:
            with self._lock:
                self.calls.append(
                    {
                        "seconds": round(time.monotonic() - started, 2),
                        "error": f"{type(exc).__name__}: {exc}"[:300],
                        "outage": server_down(exc),
                    }
                )
            raise
        if self.model.get("gym_model_server"):
            out["replies"] = [unwrap_reasoning(r) for r in out["replies"]]
        reply = out["replies"][0]
        usage = reply.meta.get("usage") or {}
        self.transcript = [*messages, reply]
        with self._lock:
            self.calls.append(
                {
                    "seconds": round(time.monotonic() - started, 2),
                    "prompt_tokens": usage.get("prompt_tokens", 0),
                    "cached_tokens": cached_tokens(usage),
                    "completion_tokens": usage.get("completion_tokens", 0),
                    "finish_reason": reply.meta.get("finish_reason"),
                    **({"lost_s": round(lost, 2)} if lost else {}),
                }
            )
        return out
