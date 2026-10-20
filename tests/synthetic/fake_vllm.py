# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""A scripted OpenAI-compatible chat server for offline tests of the generator, the scanner and the optimizer.

It answers like vLLM with a reasoning parser: the reasoning goes in `message.reasoning` and tool calls in
`message.tool_calls`. Every request body is recorded in `requests`.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class FakeVllm:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with fake._lock:
                    fake.requests.append(body)
                payload = json.dumps(fake.respond(body)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def __enter__(self) -> "FakeVllm":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()

    # -- scripted behaviour -----------------------------------------------------------------------

    def respond(self, body: dict[str, Any]) -> dict[str, Any]:
        messages = body["messages"]
        tools = [t["function"]["name"] for t in body.get("tools") or []]
        user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        user = user if isinstance(user, str) else json.dumps(user)
        thinking_off = (body.get("chat_template_kwargs") or {}).get("enable_thinking") is False
        budget = body.get("thinking_token_budget")

        content: str | None = None
        reasoning: str | None = None if thinking_off else "Considering the request."
        calls: list[tuple[str, Any]] = []
        completion_tokens = 20

        if "submit_candidate" in tools:
            # The optimizer: a premature submit (refused), an edit, validation, then the submit.
            results = [str(m.get("content")) for m in messages if m["role"] == "tool"]
            context = "\n".join(m["content"] for m in messages if m["role"] == "user" and isinstance(m["content"], str))
            revs = re.findall(r'"revision": "([0-9a-f]{16})"', "".join(results)) or re.findall(
                r"Revision: `([0-9a-f]{16})`", context
            )
            step = [
                ("submit_candidate", {"rationale": "too early", "expected_revision": revs[-1]}),
                (
                    "edit_file",
                    {
                        "path": "pipeline.yaml",
                        "old": "max_agent_steps: 15",
                        "new": "max_agent_steps: 20",
                        "expected_revision": revs[-1],
                    },
                ),
                ("validate_candidate", {}),
                ("submit_candidate", {"rationale": "more steps reach more files", "expected_revision": revs[-1]}),
            ][min(len(results), 3)]
            calls.append((step[0], json.dumps(step[1])))
        elif "report_finding" in tools:
            # The scanner's agent: the optimizer's own tool once (if any), a read of the first file that has
            # "store" in its name, a report of the first SELECT line it showed, then a final answer.
            done = [
                c["function"]["name"] for m in messages if m["role"] == "assistant" for c in (m.get("tool_calls") or [])
            ]
            own = [t for t in tools if t not in ("report_finding", "read_file", "run_python")]
            first = next(m["content"] for m in messages if m["role"] == "user")
            first = first if isinstance(first, str) else json.dumps(first)
            files = re.findall(r"^(\S+\.py) \(\d+ lines\)$", first, re.M)
            shown = "\n".join(str(m.get("content")) for m in messages if m["role"] == "tool")
            hit = re.search(r"^(\S+\.py) \(\d+ lines\), lines[\s\S]*?^\s*(\d+) \| .*SELECT", shown, re.M)
            if own and own[0] not in done:
                calls.append((own[0], json.dumps({"pattern": "SELECT"})))
            elif "read_file" in tools and "read_file" not in done and files:
                calls.append(("read_file", json.dumps({"path": next((f for f in files if "store" in f), files[0])})))
            elif hit and "report_finding" not in done:
                calls.append(
                    (
                        "report_finding",
                        json.dumps(
                            {
                                "path": hit.group(1),
                                "line_start": int(hit.group(2)),
                                "line_end": hit.group(2),
                                "cwe": "CWE-89",
                                "title": "SQL built from input",
                                "confidence": "80",
                            }
                        ),
                    )
                )
            else:
                content = "Done: reviewed the repository."
        elif body.get("response_format"):
            # A JSON-schema request from the optimizer's code (ctx.llm.ask): a fixed object.
            content = json.dumps({"keep": True, "line": 9})
        elif "prime number" in user:
            length = 4000 if budget is None else int(budget)
            reasoning = (
                "count " * length
            )  # ~length tokens at ~6 chars per word, well under the 3.5 chars/token estimate
            reasoning = reasoning[: int(length * 3.0)]
            content = "95"
            completion_tokens = length + 2
        elif "exactly the word OK" in user:
            content = "OK"
        else:
            content = "SQL injection happens when ..."
            completion_tokens = 300

        message: dict[str, Any] = {"role": "assistant", "content": content}
        if reasoning:
            message["reasoning"] = reasoning
        if calls:
            message["tool_calls"] = [
                {
                    "id": f"call_{len(self.requests)}_{k}",
                    "type": "function",
                    "function": {"name": name, "arguments": args},
                }
                for k, (name, args) in enumerate(calls)
            ]
        return {
            "id": f"chatcmpl-{len(self.requests)}",
            "object": "chat.completion",
            "created": 0,
            "model": body["model"],
            "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if calls else "stop"}],
            "usage": {
                "prompt_tokens": 50,
                "completion_tokens": completion_tokens,
                "total_tokens": 50 + completion_tokens,
            },
        }
