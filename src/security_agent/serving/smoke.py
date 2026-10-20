# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Smoke check for a local model server: does it do what the agents rely on?

Run it after a server starts and before any benchmark run. It needs only the Python standard library, so it runs on
a fresh DGX Spark. The checks:

1. `chat_basic`: a plain answer with thinking off.
2. `reasoning_surfaced`: the reasoning arrives in its own field, not in the answer.
3. `thinking_budget_honored`: a per-request thinking budget caps the reasoning. The prompt makes the model want to
   think longer than the budget, so the cap has to bind.
4. `guided_json` and `guided_json_tight_budget`: a tool-free answer follows a JSON schema and finishes, also with a
   64-token thinking budget.
5. `long_tool_argument`: a tool call with a 2,000-character argument parses.
6. `tool_loop`: the model reads a small repository through tools and ends by calling a submit tool.
7. `concurrency`: parallel requests all succeed; the aggregate throughput is reported.

    python -m security_agent.serving.smoke                        # the server on 127.0.0.1:8000
    python -m security_agent.serving.smoke --report smoke.json    # also write the details
"""

import argparse
import json
import re
import sys
import time
import traceback
import urllib.request
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_BASE_URL = "http://127.0.0.1:8000/v1"


@dataclass
class Check:
    """The outcome of one check."""

    name: str
    passed: bool
    seconds: float
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Reply:
    """The parts of a chat completion the checks look at."""

    content: str
    reasoning: str
    tool_calls: list[dict[str, Any]]
    finish_reason: str | None
    usage: dict[str, Any]

    def malformed_tool_calls(self) -> bool:
        """
        Whether the server reported a tool call it could not parse.

        :returns: True if the model stopped for a tool call but no call parsed, or a call's arguments are not JSON.
        """
        if self.finish_reason == "tool_calls" and not self.tool_calls:
            return True
        for call in self.tool_calls:
            try:
                json.loads(call["function"]["arguments"] or "{}")
            except (ValueError, KeyError, TypeError):
                return True
        return False

    def reasoning_tokens(self) -> tuple[int, str]:
        """
        Reasoning tokens, from the server's usage report or estimated from the text.

        :returns: The count and where it came from.
        """
        reported = (self.usage.get("completion_tokens_details") or {}).get("reasoning_tokens")
        if reported:
            return int(reported), "usage"
        return round(len(self.reasoning) / 3.5), "estimate"


class Client:
    """A minimal client for an OpenAI-compatible chat completions endpoint (vLLM or NIM)."""

    def __init__(self, base_url: str, model: str, timeout: float = 600.0) -> None:
        """
        Create a client.

        :param base_url: The server's base URL, ending in `/v1`.
        :param model: The served model name.
        :param timeout: Seconds to wait for one response.
        """
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        max_tokens: int,
        thinking_budget: int | None,
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> Reply:
        """
        Send one chat completion at temperature 0.

        :param messages: The conversation in OpenAI format.
        :param max_tokens: The cap on output tokens, reasoning included.
        :param thinking_budget: `None` turns thinking off; a number caps the reasoning tokens.
        :param tools: Tool definitions in OpenAI format; the model chooses whether to call one.
        :param response_format: A structured-output constraint, such as a JSON schema.
        :returns: The first choice.
        """
        body: dict[str, Any] = {"model": self.model, "messages": messages, "max_tokens": max_tokens, "temperature": 0}
        if thinking_budget is None:
            body["chat_template_kwargs"] = {"enable_thinking": False}
        else:
            body["thinking_token_budget"] = thinking_budget
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        if response_format:
            body["response_format"] = response_format
        data = _post(f"{self.base_url}/chat/completions", body, self.timeout)
        choice = data["choices"][0]
        message = choice.get("message") or {}
        return Reply(
            content=message.get("content") or "",
            reasoning=message.get("reasoning") or message.get("reasoning_content") or "",
            tool_calls=message.get("tool_calls") or [],
            finish_reason=choice.get("finish_reason"),
            usage=data.get("usage") or {},
        )


def _post(url: str, body: dict[str, Any], timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def served_models(base_url: str, timeout: float = 30.0) -> list[str]:
    """
    The model names the server lists.

    :param base_url: The server's base URL, ending in `/v1`.
    :param timeout: Seconds to wait.
    :returns: The ids from `/v1/models`.
    """
    with urllib.request.urlopen(f"{base_url.rstrip('/')}/models", timeout=timeout) as response:
        return [model["id"] for model in json.load(response)["data"]]


def _function(name: str, description: str, properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": properties, "required": list(properties)},
        },
    }


def check_chat_basic(client: Client) -> tuple[bool, dict[str, Any]]:
    """
    A plain answer with thinking off.

    :param client: The server's client.
    :returns: Whether it passed, and the details.
    """
    reply = client.chat(
        [{"role": "user", "content": "Reply with exactly the word OK and nothing else."}],
        max_tokens=64,
        thinking_budget=None,
    )
    return "OK" in reply.content.upper(), {"answer": reply.content.strip()[:200], "usage": reply.usage}


def check_reasoning(client: Client, budget: int) -> tuple[bool, dict[str, Any]]:
    """
    Reasoning arrives in its own field, and a thinking budget caps it.

    :param client: The server's client.
    :param budget: The thinking budget in tokens.
    :returns: Whether reasoning was surfaced, and the details for the budget check.
    """
    prompt = (
        "List every prime number below 300, verifying each candidate carefully in your reasoning, "
        "then give only the count as your final answer."
    )
    reply = client.chat([{"role": "user", "content": prompt}], max_tokens=budget + 1024, thinking_budget=budget)
    tokens, source = reply.reasoning_tokens()
    return bool(reply.reasoning), {
        "budget": budget,
        "reasoning_tokens": tokens,
        "reasoning_tokens_source": source,
        "answer": reply.content.strip()[:200],
        "finish_reason": reply.finish_reason,
    }


def budget_honored(details: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    """
    Judge the thinking budget from `check_reasoning`'s details.

    The cap must bind (the model reasons up to near the budget) and hold (at most a few tokens over it). Whether the
    answer still finishes is reported, not required: after the cut, Qwen answers at once, while Nemotron finishes its
    thought visibly in the answer.

    :param details: The details `check_reasoning` returned.
    :returns: Whether it passed, and the details.
    """
    budget, tokens = details["budget"], details["reasoning_tokens"]
    binding = tokens >= 0.75 * budget
    within = tokens <= budget + 16
    answered = bool(details["answer"]) and details["finish_reason"] == "stop"
    return binding and within, {**details, "binding": binding, "within": within, "answered": answered}


_HUNT_SCHEMA = {
    "type": "object",
    "properties": {
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "line_start": {"type": "integer", "minimum": 1},
                    "line_end": {"type": "integer", "minimum": 1},
                    "cwe": {"type": "string", "pattern": "^CWE-[1-9][0-9]*$"},
                    "title": {"type": "string"},
                    "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                },
                "required": ["path", "line_start", "line_end", "cwe", "title", "confidence"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["candidates"],
    "additionalProperties": False,
}
_HUNT_CODE = [
    "import sqlite3",
    "",
    "def find_user(conn: sqlite3.Connection, name: str):",
    "    query = f\"SELECT * FROM users WHERE name = '{name}'\"",
    "    return conn.execute(query).fetchall()",
]


def check_guided_json(client: Client, thinking_budget: int = 512) -> tuple[bool, dict[str, Any]]:
    """
    A tool-free answer follows a JSON schema and finishes.

    The model does not see the schema, which only constrains decoding, so the prompt explains every field it should
    fill meaningfully.

    :param client: The server's client.
    :param thinking_budget: The thinking budget in tokens.
    :returns: Whether it passed, and the details.
    """
    code = "\n".join(f"{number:>4}\t{line}" for number, line in enumerate(_HUNT_CODE, start=1))
    prompt = (
        "Report the security defects in src/users.py. Respond with JSON only. For each candidate, set confidence "
        f"(0-100) to how sure you are that it is exploitable.\n\nsrc/users.py\n{code}"
    )
    reply = client.chat(
        [{"role": "user", "content": prompt}],
        max_tokens=2048,
        thinking_budget=thinking_budget,
        response_format={
            "type": "json_schema",
            "json_schema": {"name": "hunt", "schema": _HUNT_SCHEMA, "strict": True},
        },
    )
    try:
        candidates = json.loads(reply.content)["candidates"]
        valid = isinstance(candidates, list) and all(
            re.fullmatch(r"CWE-[1-9]\d*", c["cwe"]) and c["line_end"] >= c["line_start"] >= 1 for c in candidates
        )
    except (ValueError, KeyError, TypeError) as error:
        return False, {"error": f"{type(error).__name__}: {error}", "answer": reply.content[:500]}
    return valid and reply.finish_reason == "stop", {
        "candidates": candidates,
        "expected": "src/users.py lines 4-5, CWE-89",
        "finish_reason": reply.finish_reason,
        "thinking_budget": thinking_budget,
    }


def check_long_tool_argument(client: Client, chars: int = 2000) -> tuple[bool, dict[str, Any]]:
    """
    A tool call with a long argument parses and keeps the argument.

    :param client: The server's client.
    :param chars: The argument's length in characters.
    :returns: Whether it passed, and the details.
    """
    lines: list[str] = []
    while sum(len(line) + 1 for line in lines) < chars:
        number = len(lines)
        lines.append(
            f"note line {number:03d}: the quick brown fox checks filter key {number} before building the query."
        )
    note = "\n".join(lines)
    tool = _function("record_note", "Record a note verbatim.", {"note": {"type": "string"}})
    prompt = f"Call record_note exactly once, with the following text as `note`, copied verbatim:\n\n{note}"
    reply = client.chat([{"role": "user", "content": prompt}], max_tokens=4096, thinking_budget=None, tools=[tool])
    malformed = reply.malformed_tool_calls()
    argument = ""
    if reply.tool_calls and not malformed:
        argument = json.loads(reply.tool_calls[0]["function"]["arguments"] or "{}").get("note", "")
    passed = bool(reply.tool_calls) and not malformed and len(argument) >= 0.9 * len(note)
    return passed, {
        "sent_chars": len(note),
        "argument_chars": len(argument),
        "exact": argument == note,
        "tool_calls": len(reply.tool_calls),
        "malformed": malformed,
    }


SAMPLE_REPOSITORY = {
    "README.md": "# sample\nA tiny document store used by the smoke check.\n",
    "src/sample/__init__.py": "from .store import DocumentStore\n",
    "src/sample/store.py": (
        "import sqlite3\n"
        "\n"
        "\n"
        "class DocumentStore:\n"
        "    def __init__(self, path: str):\n"
        "        self.conn = sqlite3.connect(path)\n"
        "\n"
        "    def count(self) -> int:\n"
        '        return self.conn.execute("SELECT COUNT(*) FROM docs").fetchone()[0]\n'
        "\n"
        "    def filter_documents(self, field: str, value: str):\n"
        "        sql = f\"SELECT * FROM docs WHERE {field} = '{value}'\"\n"
        "        return self.conn.execute(sql).fetchall()\n"
    ),
}
SAMPLE_FINDING = ("src/sample/store.py", 12)


def _run_repository_tool(name: str, arguments: dict[str, Any]) -> str:
    if name == "list_files":
        return "\n".join(sorted(SAMPLE_REPOSITORY))
    if name == "read_file":
        text = SAMPLE_REPOSITORY.get(str(arguments.get("path", "")).lstrip("/").removeprefix("repo/"))
        if text is None:
            return "error: no such file"
        return "\n".join(f"{number:>4}\t{line}" for number, line in enumerate(text.splitlines(), start=1))
    return f"error: unknown tool {name}"


def check_tool_loop(client: Client, thinking_budget: int, max_turns: int = 8) -> tuple[bool, dict[str, Any]]:
    """
    The model reviews a small repository through tools and ends by calling a submit tool.

    :param client: The server's client.
    :param thinking_budget: The thinking budget per turn, in tokens.
    :param max_turns: The most model turns before giving up.
    :returns: Whether it passed, and the details.
    """
    tools = [
        _function("list_files", "List the repository's files.", {}),
        _function("read_file", "Read a file, with line numbers.", {"path": {"type": "string"}}),
        _function(
            "submit_finding",
            "Submit your single most important finding. Calling this ends the review.",
            {
                "path": {"type": "string", "description": "File path relative to the repository root."},
                "line": {"type": "integer", "minimum": 1},
                "cwe": {"type": "string", "description": "CWE id like CWE-89."},
            },
        ),
    ]
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                "You review a Python repository for security defects, using only the tools. Find where a SQL query is "
                "built from caller-supplied input, read the code, then call submit_finding with the file, the line "
                "that builds the query, and the CWE id."
            ),
        },
        {"role": "user", "content": "Review the repository."},
    ]
    called: list[str] = []
    malformed = 0
    finding: dict[str, Any] = {}
    for _ in range(max_turns):
        reply = client.chat(messages, max_tokens=4096, thinking_budget=thinking_budget, tools=tools)
        if reply.malformed_tool_calls():
            malformed += 1
            break
        if not reply.tool_calls:
            break
        messages.append({"role": "assistant", "content": reply.content, "tool_calls": reply.tool_calls})
        for call in reply.tool_calls:
            name = call["function"]["name"]
            arguments = json.loads(call["function"]["arguments"] or "{}")
            called.append(name)
            if name == "submit_finding":
                finding = arguments
                break
            messages.append(
                {"role": "tool", "tool_call_id": call["id"], "content": _run_repository_tool(name, arguments)}
            )
        if finding:
            break
    path = str(finding.get("path", "")).lstrip("/").removeprefix("repo/")
    located = path == SAMPLE_FINDING[0] and abs(int(finding.get("line") or 0) - SAMPLE_FINDING[1]) <= 2
    passed = bool(finding) and any(name in called for name in ("list_files", "read_file")) and not malformed
    return passed, {"tool_calls": called, "malformed": malformed, "finding": finding, "located_correctly": located}


def check_concurrency(client: Client, requests: int) -> tuple[bool, dict[str, Any]]:
    """
    Parallel requests all succeed.

    :param client: The server's client.
    :param requests: How many requests to send at once.
    :returns: Whether it passed, and the details with the aggregate throughput.
    """
    prompt = [{"role": "user", "content": "Explain SQL injection to a junior developer in about 150 words."}]

    def one(_: int) -> tuple[float, int]:
        started = time.monotonic()
        reply = client.chat(prompt, max_tokens=400, thinking_budget=None)
        return time.monotonic() - started, int(reply.usage.get("completion_tokens") or 0)

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=requests) as pool:
        results = list(pool.map(one, range(requests)))
    wall = time.monotonic() - started
    tokens = sum(count for _, count in results)
    return len(results) == requests and all(count > 0 for _, count in results), {
        "requests": requests,
        "wall_seconds": round(wall, 1),
        "completion_tokens": tokens,
        "aggregate_tokens_per_second": round(tokens / wall, 1) if wall else None,
    }


def run_smoke(
    client: Client,
    *,
    concurrency: int = 8,
    budget: int = 512,
    tool_loop_budget: int = 1024,
    log: Callable[[str], None] = print,
) -> list[Check]:
    """
    Run every check. A check that raises counts as failed.

    :param client: The server's client.
    :param concurrency: How many parallel requests the concurrency check sends.
    :param budget: The thinking budget for the reasoning checks.
    :param tool_loop_budget: The thinking budget per turn in the tool loop.
    :param log: Where to write one line per check.
    :returns: The checks, in order.
    """
    checks: list[Check] = []

    def record(name: str, run: Callable[[], tuple[bool, dict[str, Any]]]) -> dict[str, Any]:
        started = time.monotonic()
        try:
            passed, details = run()
        except Exception as error:
            passed = False
            details = {"error": f"{type(error).__name__}: {error}", "trace": traceback.format_exc(limit=3)}
        check = Check(name, bool(passed), round(time.monotonic() - started, 1), details)
        checks.append(check)
        summary = json.dumps(details, default=str)[:240]
        log(f"{'PASS' if check.passed else 'FAIL'}  {name:<26} {check.seconds:>6.1f}s  {summary}")
        return details

    reasoning = record("reasoning_surfaced", lambda: check_reasoning(client, budget))
    if "error" not in reasoning:
        record("thinking_budget_honored", lambda: budget_honored(reasoning))
    record("chat_basic", lambda: check_chat_basic(client))
    record("guided_json", lambda: check_guided_json(client))
    record("guided_json_tight_budget", lambda: check_guided_json(client, thinking_budget=64))
    record("long_tool_argument", lambda: check_long_tool_argument(client))
    record("tool_loop", lambda: check_tool_loop(client, tool_loop_budget))
    record("concurrency", lambda: check_concurrency(client, concurrency))
    return checks


def main(argv: Sequence[str] | None = None) -> int:
    """
    Command-line entry point.

    :param argv: The arguments; `sys.argv[1:]` when `None`.
    :returns: 0 if every check passed, 1 otherwise.
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="the server's base URL, ending in /v1")
    parser.add_argument("--model", help="the served model name; default: the only model the server lists")
    parser.add_argument("--concurrency", type=int, default=8, help="parallel requests; the servers run 8 sequences")
    parser.add_argument("--budget", type=int, default=512, help="thinking budget for the reasoning checks")
    parser.add_argument("--timeout", type=float, default=600.0, help="seconds to wait for one response")
    parser.add_argument("--report", type=Path, help="also write every check's details to this JSON file")
    args = parser.parse_args(argv)

    model = args.model
    if model is None:
        models = served_models(args.base_url)
        if len(models) != 1:
            print(f"error: the server lists {models}; pass --model", file=sys.stderr)
            return 1
        model = models[0]
    print(f"smoke check: {model} on {args.base_url}")
    checks = run_smoke(Client(args.base_url, model, args.timeout), concurrency=args.concurrency, budget=args.budget)
    passed = all(check.passed for check in checks)
    if args.report:
        report = {"base_url": args.base_url, "model": model, "passed": passed, "checks": [asdict(c) for c in checks]}
        args.report.write_text(json.dumps(report, indent=1, default=str) + "\n")
    print(f"{sum(c.passed for c in checks)} of {len(checks)} checks passed")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
