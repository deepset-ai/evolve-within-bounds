# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Model access for the optimizer's code (`ctx.llm`), within a budget per repository.

One `ModelGateway` serves one tool set or step during one scan. Each request is checked and clipped to the per-call
limits (`CALL_LIMITS`); calls beyond the budget (model calls, output tokens) get an error answer instead of a model
call. Answers are `{"text", "json", "error"}`; errors never raise, so the code can decide what to do. Every call is
logged in `calls` for the scan's record.
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import threading
import time
from typing import Any

from haystack.dataclasses import ChatMessage

from security_agent.generator import Generator, cached_tokens, server_down

FINDING_KEYS = (
    "path",
    "line_start",
    "line_end",
    "cwe",
    "title",
    "severity",
    "confidence",
    "source",
    "sink",
    "missing_control",
)
# One model call from the optimizer's code: output tokens, thinking budget, prompt characters.
CALL_LIMITS = {"max_tokens": 16_384, "thinking": 8_192, "prompt_chars": 200_000}


def compact(findings: list[dict]) -> list[dict]:
    """What a scan record keeps of a component's input and output, for the failure digests."""
    return [{k: f.get(k) for k in ("path", "line_start", "line_end", "cwe", "confidence", "title")} for f in findings]


class ModelGateway:
    def __init__(self, model: dict[str, Any], max_calls: int = 40, max_completion_tokens: int = 60_000) -> None:
        self.model = model
        self.max_calls = max_calls
        self.max_completion_tokens = max_completion_tokens
        self.max_parallel = int(model.get("concurrency", 8))
        self.limits = dict(CALL_LIMITS)
        self.calls: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._granted = 0

    def _spent(self) -> int:
        return sum(int(c.get("completion_tokens", 0)) for c in self.calls)

    def _check(self, request: Any) -> tuple[dict | None, str | None]:
        if not isinstance(request, dict) or not isinstance(request.get("prompt"), str) or not request["prompt"].strip():
            return None, "each request needs a non-empty prompt string"
        system = request.get("system") or ""
        if not isinstance(system, str):
            return None, "system must be a string"
        if len(request["prompt"]) + len(system) > self.limits["prompt_chars"]:
            return None, f"prompt and system together are limited to {self.limits['prompt_chars']} characters"
        schema = request.get("schema")
        if schema is not None and not isinstance(schema, dict):
            return None, "schema must be a JSON schema object or None"
        thinking = request.get("thinking")
        thinking = 1024 if thinking is None else thinking
        max_tokens = request.get("max_tokens") or 2048
        if (
            not isinstance(thinking, int)
            or not isinstance(max_tokens, int)
            or isinstance(thinking, bool)
            or isinstance(max_tokens, bool)
        ):
            return None, "thinking and max_tokens must be integers"
        thinking = max(0, min(thinking, self.limits["thinking"]))
        max_tokens = max(256, min(max_tokens, self.limits["max_tokens"]))
        if thinking and max_tokens < thinking + 512:
            max_tokens = min(self.limits["max_tokens"], thinking + 512)
        return {
            "prompt": request["prompt"],
            "system": system,
            "schema": schema,
            "thinking": thinking,
            "max_tokens": max_tokens,
        }, None

    def _complete(self, messages: list, max_tokens: int, thinking: int | None, extra: dict | None) -> ChatMessage:
        generator = Generator(self.model, max_tokens=max_tokens, thinking_budget=thinking, extra=extra)
        reply = generator.run(messages)["replies"][0]
        reply.meta["lost_s"] = (generator.calls[-1] if generator.calls else {}).get("lost_s", 0)
        return reply

    def _call(self, request: dict) -> dict:
        started = time.monotonic()
        record: dict[str, Any] = {"thinking": request["thinking"], "max_tokens": request["max_tokens"]}
        extra = None
        if request["schema"] is not None:
            extra = {
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {"name": "answer", "schema": request["schema"], "strict": True},
                }
            }
        messages = ([ChatMessage.from_system(request["system"])] if request["system"] else []) + [
            ChatMessage.from_user(request["prompt"])
        ]
        try:
            reply = self._complete(messages, request["max_tokens"], request["thinking"] or None, extra)
        except Exception as exc:  # noqa: BLE001 - the code gets the error and decides
            record.update(
                seconds=round(time.monotonic() - started, 2),
                error=f"{type(exc).__name__}: {exc}"[:300],
                outage=server_down(exc),
            )
            with self._lock:
                self.calls.append(record)
            return {"text": "", "json": None, "error": record["error"]}
        usage = reply.meta.get("usage") or {}
        text = reply.text or ""
        parsed, json_error = None, None
        if request["schema"] is not None:
            try:
                parsed = json.loads(text)
            except ValueError as exc:
                json_error = f"the answer is not valid JSON: {exc}"[:200]
        record.update(
            seconds=round(time.monotonic() - started, 2),
            prompt_tokens=usage.get("prompt_tokens", 0),
            cached_tokens=cached_tokens(usage),
            completion_tokens=usage.get("completion_tokens", 0),
            finish_reason=reply.meta.get("finish_reason"),
            **({"lost_s": reply.meta["lost_s"]} if reply.meta.get("lost_s") else {}),
        )
        if json_error:
            record["json_error"] = json_error
        with self._lock:
            self.calls.append(record)
        return {"text": text, "json": parsed, "error": json_error}

    def ask_many(self, requests: list[Any]) -> list[dict]:
        """Several model calls in parallel, within the budget; answers in order."""
        results: list[dict | None] = [None] * len(requests)
        jobs = []
        for i, request in enumerate(requests if isinstance(requests, list) else []):
            clean, problem = self._check(request)
            with self._lock:
                if problem is None and self._granted >= self.max_calls:
                    problem = f"budget: at most {self.max_calls} model calls per repository; decide with what you have"
                elif problem is None and self._spent() >= self.max_completion_tokens:
                    problem = (
                        f"budget: at most {self.max_completion_tokens} output tokens per repository; decide "
                        "with what you have"
                    )
                elif problem is None:
                    self._granted += 1
            if problem:
                results[i] = {"text": "", "json": None, "error": problem}
            else:
                jobs.append((i, clean))
        if jobs:
            with cf.ThreadPoolExecutor(max_workers=min(len(jobs), self.max_parallel)) as pool:
                for (i, _), answer in zip(jobs, pool.map(lambda job: self._call(job[1]), jobs), strict=True):
                    results[i] = answer
        return [r or {"text": "", "json": None, "error": "no request"} for r in results]


class StubGateway(ModelGateway):
    """For the contract test: every request gets an error answer, as when the budget is spent. No model is called."""

    def __init__(self) -> None:
        super().__init__({}, max_calls=0)

    def ask_many(self, requests: list[Any]) -> list[dict]:
        """Every request is answered with an error (the contract test's model)."""
        n = len(requests) if isinstance(requests, list) else 0
        return [{"text": "", "json": None, "error": "no model in the contract test"} for _ in range(n)]
