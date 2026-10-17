# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The scanner: a Haystack Agent that the self-improvement loop extends with tools and steps it writes.

**A candidate** is a directory:
- `pipeline.yaml`: a Haystack pipeline;
- `prompts/`: the agent's system prompt (`system_prompt`, plain text) and its first user message (`user_prompt`, a
  Jinja2 template with `file_list`, `file_count` and `notes`);
- `tools/`: Python code the optimizer wrote.

**Components** (`ALLOWED`; anything else is refused):
- `security_agent.synthetic.agent.ScanAgent`, exactly one, named `agent`: a Haystack `Agent` on the configured model.
- `security_agent.synthetic.agent.CodeStep`: a step the optimizer wrote (`KIND = "step"`, `run(ctx)`), before or
  after the agent. At most `MAX_STEPS`.
- `security_agent.synthetic.normalize.Normalizer`, named `normalizer`: the output, with tau 0 (no confidence threshold).

Findings flow through the `findings` sockets: steps before the agent, the agent, steps after it, the normalizer.

**The agent's tools.** Built in, fixed by the harness:
- `report_finding`: always on, and the only way the agent reports. The scorer reads only reported findings.
- `read_file`: numbered lines of a repository file, at most `read_file_lines` per call.
- `run_python`: Monty's Python (`MontyPythonTool`). A fresh interpreter per call in a worker process; no files, no
  network.

The optimizer's own tools are `tools/<name>.py` files with `KIND = "tool"`, `DESCRIPTION`, `PARAMETERS` (a JSON
schema) and `run(ctx, **arguments)`. They are listed in `agent.tools`.

**`ctx`** (`ScanContext`) is what the optimizer's code sees during one scan:
- the repository (`security_agent.synthetic.repo.Repo`, read-only);
- the model (`ctx.llm`, budgeted per repository);
- the findings so far, with `report`, `retract` and `update`;
- `note` (text for the agent's first message);
- `state` (shared by all code in one scan).

The code runs in the scanner's process. `security_agent.synthetic.codecheck` refuses code that imports file, process
or network modules; the boundary around the scanner is the OpenShell sandbox every scan runs in
(`security_agent.synthetic.sandbox`).

**Limits per repository** are set in `pipeline.yaml` within `RANGES`:
- the agent: steps, output tokens per call, thinking budget, total prompt and output tokens, wall time;
- the optimizer's code: model calls and output tokens.

When a limit is reached, the agent stops and what it reported so far is kept. Only a model-server outage makes a scan
incomplete. Every scan starts afresh: nothing is reused between scans.
"""

from __future__ import annotations

import difflib
import functools
import hashlib
import inspect
import json
import re
import threading
import time
import traceback
import uuid
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import jinja2
import yaml
from haystack import Pipeline, component
from haystack.core.serialization import allow_deserialization_module
from haystack.dataclasses import ChatMessage

from security_agent.generator import Generator, malformed_tool_calls, server_down
from security_agent.synthetic.codecheck import MAX_LINES as MAX_CODE_LINES
from security_agent.synthetic.codecheck import check_code
from security_agent.synthetic.config import load_yaml, resolve
from security_agent.synthetic.gateway import CALL_LIMITS, FINDING_KEYS, ModelGateway, StubGateway, compact
from security_agent.synthetic.normalize import Normalizer
from security_agent.synthetic.repo import Repo, line_counts
from security_agent.synthetic.schema import Cost, Coverage, Finding, ScanResult
from security_agent.synthetic.staging import StagedRepo

PIPELINE = "pipeline.yaml"
SCAN_AGENT = "security_agent.synthetic.agent.ScanAgent"  # the component types, as pipeline.yaml names them
CODE_STEP = "security_agent.synthetic.agent.CodeStep"
NORMALIZER = "security_agent.synthetic.normalize.Normalizer"
NAME = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
CWE = re.compile(r"^CWE-[1-9][0-9]*$")
MAX_STEPS = 6
MAX_CODE_FILES = 16
MAX_DESCRIPTION_CHARS = 3_000  # a tool's DESCRIPTION, as the agent reads it
BUILTIN_TOOLS = ("read_file", "run_python")  # report_finding is always on and not listed
TEMPLATE_VARIABLES = {"file_list", "file_count", "notes"}
MAX_PROMPT_CHARS = 40_000

# (type, low, high). The agent's own limits are per repository unless stated otherwise.
RANGES: dict[str, dict[str, tuple[type, float, float]]] = {
    SCAN_AGENT: {
        "max_agent_steps": (int, 3, 300),
        "max_tokens": (int, 1_024, 32_768),  # per model call, thinking included
        "thinking_budget": (int, 0, 16_384),  # per model call; 0 turns thinking off
        "temperature": (float, 0.0, 1.0),
        "read_file_lines": (int, 20, 2_000),  # per read_file call
        "file_list_chars": (int, 0, 60_000),  # the file list in the first message
        "tool_output_chars": (int, 500, 60_000),  # per tool result shown to the agent
        "tool_timeout_s": (int, 5, 900),  # per call of one of the optimizer's tools
        "tool_model_calls": (int, 0, 600),  # model calls from the optimizer's tools
        "tool_completion_tokens": (int, 0, 600_000),  # their output tokens
        "scan_prompt_tokens": (int, 50_000, 10_000_000),  # the agent's own prompt tokens
        "scan_completion_tokens": (int, 5_000, 600_000),  # the agent's own output tokens
        "timeout_s": (int, 120, 5_400),  # wall time of the agent, its tools included
    },
    CODE_STEP: {"max_calls": (int, 0, 600), "max_completion_tokens": (int, 0, 600_000), "timeout_s": (int, 10, 3_600)},
    NORMALIZER: {"tau": (int, 0, 100), "max_per_location": (int, 1, 3)},
}
PATH_PARAMS = {SCAN_AGENT: {"system_prompt": "prompts/", "user_prompt": "prompts/"}, CODE_STEP: {"code": "tools/"}}
INJECTED = {SCAN_AGENT: ("model", "scan"), CODE_STEP: ("model", "scan")}
TOP_LEVEL = {"components", "connections", "metadata", "max_runs_per_component", "connection_type_validation"}


class BudgetSpent(Exception):
    """A per-repository limit of the agent was reached: it stops, and what it reported so far is kept."""


# -- what the optimizer's code sees ----------------------------------------------------------------


class Llm:
    """`ctx.llm`: the model, for the optimizer's code. Errors and spent budgets come back as `error`, never raised."""

    def __init__(self, gateway: ModelGateway | None) -> None:
        self._gateway = gateway

    def ask(
        self, prompt: str, system: str = "", schema: dict | None = None, max_tokens: int = 2048, thinking: int = 1024
    ) -> dict:
        """One model call; returns `{"text", "json", "error"}`."""
        return self.ask_many(
            [{"prompt": prompt, "system": system, "schema": schema, "max_tokens": max_tokens, "thinking": thinking}]
        )[0]

    def ask_many(self, requests: list[dict]) -> list[dict]:
        """Several model calls in parallel, answers in order."""
        if not isinstance(requests, list):
            return [{"text": "", "json": None, "error": "ask_many takes a list of requests"}]
        if self._gateway is None:
            return [{"text": "", "json": None, "error": "no model budget here (0 calls allowed)"} for _ in requests]
        return self._gateway.ask_many(requests)


class ScanContext:
    """`ctx`: one scan's repository, model, findings, notes and shared state. See the module docstring."""

    def __init__(self, root: str, files: list[str]) -> None:
        self.repo = Repo(root, list(files))
        self.counts = line_counts(Path(root), list(files))
        self.findings: list[dict] = []
        self.notes: list[str] = []
        self.state: dict[str, Any] = {}
        self.llm = Llm(None)
        self._lock = threading.RLock()

    def _problem(self, f: dict) -> str | None:
        if f.get("path") not in self.counts:
            close = difflib.get_close_matches(str(f.get("path")), list(self.counts), n=3)
            return f"unknown path {f.get('path')!r}" + (
                f"; did you mean {close}?" if close else "; use a path from the file list"
            )
        start, end = f.get("line_start"), f.get("line_end")
        if not isinstance(start, int) or not isinstance(end, int) or isinstance(start, bool) or isinstance(end, bool):
            return "line_start and line_end must be integers"
        if not 1 <= start <= end <= self.counts[f["path"]]:
            return f"lines must satisfy 1 <= line_start <= line_end <= {self.counts[f['path']]} (the file's length)"
        if not isinstance(f.get("cwe"), str) or not CWE.match(f["cwe"]):
            return "cwe must look like CWE-89"
        if not isinstance(f.get("title"), str) or not f["title"].strip():
            return "a short title is required"
        if not isinstance(f.get("confidence"), int) or not 0 <= f["confidence"] <= 100:
            return "confidence must be an integer from 0 to 100"
        return None

    def report(
        self,
        path: str,
        line_start: int,
        line_end: int | None = None,
        cwe: str = "",
        title: str = "",
        confidence: int = 50,
        severity: str = "medium",
        source: str = "",
        sink: str = "",
        missing_control: str = "",
    ) -> int:
        """Add a finding; returns its id. Raises ValueError (with the reason) for an invalid one."""
        line_start, line_end, confidence = (
            _as_int(line_start),
            _as_int(line_start if line_end is None else line_end),
            _as_int(confidence),
        )
        finding = {
            "path": path,
            "line_start": line_start,
            "line_end": line_end,
            "cwe": str(cwe).strip().upper(),
            "title": str(title)[:200],
            "confidence": confidence,
            "severity": severity if severity in ("high", "medium", "low") else "medium",
            "source": str(source)[:300],
            "sink": str(sink)[:300],
            "missing_control": str(missing_control)[:300],
        }
        if problem := self._problem(finding):
            raise ValueError(problem)
        with self._lock:
            new_id = max((int(f["id"]) for f in self.findings), default=-1) + 1
            finding["id"] = new_id
            self.findings.append(finding)
            return new_id

    def retract(self, finding_id: int) -> bool:
        """Remove a finding; False if there is none with that id."""
        with self._lock:
            before = len(self.findings)
            self.findings = [f for f in self.findings if f.get("id") != finding_id]
            return len(self.findings) < before

    def update(self, finding_id: int, **fields: Any) -> bool:
        """Change a finding's lines (same file), cwe, title, confidence or severity. Raises ValueError if invalid."""
        allowed = {
            "line_start",
            "line_end",
            "cwe",
            "title",
            "confidence",
            "severity",
            "source",
            "sink",
            "missing_control",
        }
        if unknown := set(fields) - allowed:
            raise ValueError(f"cannot update {sorted(unknown)}; allowed: {sorted(allowed)}")
        with self._lock:
            for i, f in enumerate(self.findings):
                if f.get("id") == finding_id:
                    changed = {
                        **f,
                        **{
                            k: _as_int(v) if k in ("line_start", "line_end", "confidence") else v
                            for k, v in fields.items()
                        },
                    }
                    if problem := self._problem(changed):
                        raise ValueError(problem)
                    self.findings[i] = changed
                    return True
        return False

    def note(self, text: str) -> None:
        """Text for the agent's first message (from a step before the agent)."""
        self.notes.append(str(text)[:20_000])


_CONTEXTS: dict[str, ScanContext] = {}


def context(key: str) -> ScanContext:
    """The scan context registered under `key`."""
    return _CONTEXTS[key]


def load_code(path: Path) -> ModuleType:
    """
    Load one of the optimizer's files afresh.

    One module per scan: module globals are not shared between scans. Compiled here, not imported, so that no
    `__pycache__` is written into the candidate.
    """
    path = Path(path)
    module = ModuleType(f"candidate_{uuid.uuid4().hex[:12]}")
    module.__file__ = str(path)
    code = compile(path.read_text(encoding="utf-8"), str(path), "exec")
    exec(code, module.__dict__)  # noqa: S102 - the scan runs in the OpenShell sandbox
    return module


def call_with_timeout(fn: Callable[[], Any], timeout_s: float) -> Any:
    """`fn()` in a thread; TimeoutError after `timeout_s` (the thread is abandoned: Python cannot stop it)."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller's thread
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True, name="candidate-code")
    thread.start()
    thread.join(timeout_s)
    if thread.is_alive():
        raise TimeoutError(f"did not finish within {timeout_s:g} s")
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _error_text(exc: BaseException) -> str:
    return "".join(traceback.format_exception(exc))[-1500:]


def _as_int(value: Any) -> Any:
    """Models often send numbers as strings ("42") or floats (42.0)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return value


def _findings_in(findings: list[dict] | None, ctx: ScanContext) -> list[dict]:
    """The incoming findings, re-validated and with fresh ids."""
    out: list[dict] = []
    for f in findings or []:
        item = {k: f.get(k) for k in FINDING_KEYS}
        item.setdefault("confidence", 50)
        if item.get("confidence") is None:
            item["confidence"] = 50
        if ctx._problem(item) is None:
            out.append({**item, "id": len(out)})
    return out


# -- the built-in tools ----------------------------------------------------------------------------

REPORT_PARAMETERS = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "description": "the file, as in the file list"},
        "line_start": {"type": "integer", "description": "first line of the vulnerable statement"},
        "line_end": {"type": "integer", "description": "last line of it (the same as line_start for one line)"},
        "cwe": {"type": "string", "description": "the weakness, e.g. CWE-89"},
        "title": {"type": "string", "description": "a short title"},
        "confidence": {
            "type": "integer",
            "description": "0 to 100: how sure you are that this is a real, exploitable vulnerability",
        },
        "explanation": {"type": "string", "description": "what is dangerous and which check is missing"},
    },
    "required": ["path", "line_start", "line_end", "cwe", "title"],
}
READ_PARAMETERS = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "description": "a file from the file list"},
        "start_line": {"type": "integer", "description": "first line to show (default 1)"},
        "end_line": {"type": "integer", "description": "last line to show (default: as many as allowed)"},
    },
    "required": ["path"],
}

_MONTY = None
_MONTY_LOCK = threading.Lock()


def monty_tool() -> Any:
    """One `MontyPythonTool` for the whole process: its worker pool is shared, every call is a fresh interpreter."""
    global _MONTY
    with _MONTY_LOCK:
        if _MONTY is None:
            from haystack_integrations.tools.monty import MontyPythonTool

            _MONTY = MontyPythonTool(max_output_chars=8_000)
        return _MONTY


# -- the components --------------------------------------------------------------------------------


@component
class ScanAgent:
    """The scanning agent. See the module docstring; the limits are in `RANGES`."""

    def __init__(  # noqa: PLR0913, PLR0917 - the init parameters a candidate's pipeline.yaml sets
        self,
        system_prompt: str,
        user_prompt: str,
        tools: list[str] | None = None,
        model: dict[str, Any] | None = None,
        scan: str = "",
        max_agent_steps: int = 15,
        max_tokens: int = 4096,
        thinking_budget: int = 1024,
        temperature: float = 0.0,
        read_file_lines: int = 150,
        file_list_chars: int = 8_000,
        tool_output_chars: int = 8_000,
        tool_timeout_s: int = 60,
        tool_model_calls: int = 0,
        tool_completion_tokens: int = 0,
        scan_prompt_tokens: int = 1_500_000,
        scan_completion_tokens: int = 60_000,
        timeout_s: int = 1_200,
    ) -> None:
        self.system_prompt, self.user_prompt = system_prompt, user_prompt
        self.tools = list(tools or [])
        self.model, self.scan = model or {}, scan
        self.max_agent_steps, self.max_tokens, self.thinking_budget, self.temperature = (
            max_agent_steps,
            max_tokens,
            thinking_budget,
            temperature,
        )
        self.read_file_lines, self.file_list_chars, self.tool_output_chars = (
            read_file_lines,
            file_list_chars,
            tool_output_chars,
        )
        self.tool_timeout_s, self.tool_model_calls, self.tool_completion_tokens = (
            tool_timeout_s,
            tool_model_calls,
            tool_completion_tokens,
        )
        self.scan_prompt_tokens, self.scan_completion_tokens, self.timeout_s = (
            scan_prompt_tokens,
            scan_completion_tokens,
            timeout_s,
        )

    # The record of one run, filled by the tools.
    def _tool(
        self,
        name: str,
        description: str,
        parameters: dict,
        fn: Callable[..., str],
        log: list[dict],
        timeout_s: float | None = None,
    ) -> Any:
        from haystack.tools import Tool

        limit = self.tool_output_chars

        def invoke(**arguments: Any) -> str:
            started = time.monotonic()
            entry: dict[str, Any] = {"tool": name, "args": json.dumps(arguments, default=str)[:600]}
            try:
                value = call_with_timeout(lambda: fn(**arguments), timeout_s) if timeout_s else fn(**arguments)
                text = value if isinstance(value, str) else json.dumps(value, default=str, indent=1)
                entry["ok"] = True
            except Exception as exc:  # noqa: BLE001 - the agent reads the error and can try again
                text = (
                    f"error: {type(exc).__name__}: {exc}"
                    if isinstance(exc, (ValueError, TypeError, KeyError, TimeoutError))
                    else f"error:\n{_error_text(exc)}"
                )
                entry.update(ok=False, error=text[-400:])
            entry["seconds"] = round(time.monotonic() - started, 3)
            entry["chars"] = len(text)
            log.append(entry)
            if len(text) > limit:
                text = text[:limit] + f"\n... [{len(text) - limit} more characters cut; ask for less]"
            return text

        return Tool(name=name, description=description, parameters=parameters, function=invoke)

    def _builtin_tools(self, ctx: ScanContext, log: list[dict], reads: list[dict]) -> list:
        n = self.read_file_lines

        def read_file(path: str, start_line: int = 1, end_line: int | None = None) -> str:
            if path not in ctx.counts:
                close = difflib.get_close_matches(str(path), list(ctx.counts), n=3)
                raise ValueError(f"unknown path {path!r}" + (f"; did you mean {close}?" if close else ""))
            total = ctx.counts[path]
            start = max(1, int(start_line or 1))
            end = min(total, int(end_line) if end_line else start + n - 1, start + n - 1)
            if start > total:
                return f"{path} has only {total} lines"
            lines = ctx.repo.lines(path)
            reads.append({"path": path, "start": start, "end": end})
            body = "\n".join(f"{i:>5} | {lines[i - 1]}" for i in range(start, end + 1))
            more = f"\n(lines {end + 1}-{total} not shown; at most {n} lines per call)" if end < total else ""
            return f"{path} ({total} lines), lines {start}-{end}:\n{body}{more}"

        def report_finding(
            path: str, line_start: int, line_end: int, cwe: str, title: str, confidence: int = 50, explanation: str = ""
        ) -> str:
            finding_id = ctx.report(path, line_start, line_end, cwe, title, confidence, missing_control=explanation)
            return f"reported finding #{finding_id}"

        tools = [
            self._tool(
                "report_finding",
                "Report one security vulnerability. Only reported findings count. Report the exact "
                "line(s) of the vulnerable statement.",
                REPORT_PARAMETERS,
                report_finding,
                log,
            )
        ]
        if "read_file" in self.tools:
            tools.append(
                self._tool(
                    "read_file",
                    f"Read numbered lines of a repository file (at most {n} lines per call).",
                    READ_PARAMETERS,
                    read_file,
                    log,
                )
            )
        if "run_python" in self.tools:
            monty = monty_tool()
            tools.append(
                self._tool(monty.name, monty.description, monty.parameters, lambda code: monty.invoke(code=code), log)
            )
        return tools

    def _code_tools(self, ctx: ScanContext, log: list[dict], errors: list[str]) -> list:
        tools = []
        for rel in self.tools:
            if rel in BUILTIN_TOOLS:
                continue
            path = Path(rel)
            try:
                module = load_code(path)
                fn = module.run
                tools.append(
                    self._tool(
                        path.stem,
                        str(module.DESCRIPTION),
                        dict(module.PARAMETERS),
                        lambda _fn=fn, **arguments: _fn(ctx, **arguments),
                        log,
                        timeout_s=self.tool_timeout_s,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - the tool is left out; the record says why
                errors.append(f"{path.name}: {_error_text(exc)[-600:]}")
        return tools

    def _user_message(self, ctx: ScanContext) -> str:
        entries = [f"{p} ({ctx.counts[p]} lines)" for p in sorted(ctx.counts)]
        listing: list[str] = []
        used = 0
        for entry in entries:
            if used + len(entry) + 1 > self.file_list_chars:
                listing.append(f"... and {len(entries) - len(listing)} more files")
                break
            listing.append(entry)
            used += len(entry) + 1
        template = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False).from_string(
            Path(self.user_prompt).read_text(encoding="utf-8")
        )
        return template.render(file_list="\n".join(listing), file_count=len(entries), notes=list(ctx.notes))

    @component.output_types(findings=list[dict], record=dict)
    def run(self, findings: list[dict] | None = None) -> dict[str, Any]:
        """Run the agent on the repository; returns its findings and its record."""
        from haystack.components.agents import Agent

        ctx = context(self.scan)
        ctx.findings = _findings_in(findings, ctx)
        received = [dict(f) for f in ctx.findings]
        gateway = (
            ModelGateway(self.model, self.tool_model_calls, self.tool_completion_tokens)
            if self.tool_model_calls
            else None
        )
        ctx.llm = Llm(gateway)
        log: list[dict] = []
        reads: list[dict] = []
        load_errors: list[str] = []
        started = time.monotonic()
        generator: Generator | None = None

        def guard() -> None:
            calls = generator.calls if generator else []
            if sum(int(c.get("prompt_tokens", 0)) for c in calls) >= self.scan_prompt_tokens:
                raise BudgetSpent(f"prompt tokens: {self.scan_prompt_tokens} per repository")
            if sum(int(c.get("completion_tokens", 0)) for c in calls) >= self.scan_completion_tokens:
                raise BudgetSpent(f"output tokens: {self.scan_completion_tokens} per repository")
            # Time lost on a hung model server (until the failover) is not the agent's: it does not count.
            lost = sum(float(c.get("lost_s", 0)) for c in calls + (gateway.calls if gateway else []))
            if time.monotonic() - started - lost >= self.timeout_s:
                raise BudgetSpent(f"time: {self.timeout_s} s per repository")

        generator = Generator(
            self.model,
            max_tokens=self.max_tokens,
            thinking_budget=self.thinking_budget or None,
            temperature=self.temperature,
            before_call=guard,
        )
        generator.run = _retrying_malformed(generator.run, log)  # type: ignore[method-assign]
        tools = self._builtin_tools(ctx, log, reads) + self._code_tools(ctx, log, load_errors)
        agent = Agent(
            chat_generator=generator,
            tools=tools,
            system_prompt=Path(self.system_prompt).read_text(encoding="utf-8"),
            exit_conditions=["text"],
            max_agent_steps=self.max_agent_steps,
            tool_concurrency_limit=1,
            required_variables=None,
        )
        stop, outage = "answered", False
        try:
            agent.warm_up()
            agent.run(messages=[ChatMessage.from_user(self._user_message(ctx))])
            if len([c for c in generator.calls if "error" not in c]) >= self.max_agent_steps:
                stop = "max_steps"
        except Exception as exc:  # noqa: BLE001 - the agent stops; what it reported is kept
            cause = _cause(exc, BudgetSpent)
            if cause is not None:
                stop = f"budget: {cause}"
            else:
                outage = server_down(exc)
                stop = ("outage: " if outage else "error: ") + f"{type(exc).__name__}: {exc}"[:300]
        calls = generator.calls
        code_calls = gateway.calls if gateway else []
        record = {
            "component": "agent",
            "stop": stop,
            "outage": outage or any(c.get("outage") for c in code_calls),
            "steps": len([c for c in calls if "error" not in c]),
            "seconds": round(time.monotonic() - started, 2),
            "calls": calls,
            "code_calls": code_calls,
            "tool_calls": log,
            "reads": reads,
            "load_errors": load_errors,
            "received": compact(received),
            "reported": [
                {**c, "missing_control": f.get("missing_control", "")[:300]}
                for c, f in zip(compact(ctx.findings), ctx.findings, strict=True)
            ],
            "trajectory": compact_messages(generator.transcript),
        }
        return {"findings": [dict(f) for f in ctx.findings], "record": record}


def _cause(exc: BaseException | None, kind: type) -> BaseException | None:
    seen = set()
    while exc is not None and id(exc) not in seen:
        if isinstance(exc, kind):
            return exc
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return None


def _retrying_malformed(run: Callable[..., dict], log: list[dict], retries: int = 2) -> Callable[..., dict]:
    """
    Ask the model again when it writes tool-call arguments that are not JSON (up to `retries` times).

    Models sometimes do, especially for long arguments. The generator drops such a call, and the agent would read the
    empty reply as its final answer.
    """

    @functools.wraps(run)  # the Agent checks run's signature for `tools`
    def wrapped(*args: Any, **kwargs: Any) -> dict:
        for attempt in range(retries + 1):
            out = run(*args, **kwargs)
            if not malformed_tool_calls(out["replies"][0]) or attempt == retries:
                return out
            log.append(
                {
                    "tool": "(malformed tool call)",
                    "ok": False,
                    "error": "the arguments were not valid JSON; asked again",
                }
            )
        return out

    return wrapped


def compact_messages(
    messages: list[ChatMessage], text_chars: int = 3_000, reasoning_chars: int = 4_000, result_chars: int = 1_500
) -> list[dict]:
    """
    An agent's conversation for the record, each part shortened.

    The first user message, then each step's reasoning, text, tool calls and tool results. The system prompt is left
    out (it is in the candidate).
    """
    out = []
    for m in messages:
        role = m.role.value
        if role == "system":
            continue
        item: dict[str, Any] = {"role": role}
        if m.text:
            item["text"] = m.text[:text_chars] + ("..." if len(m.text) > text_chars else "")
        if m.reasoning is not None and m.reasoning.reasoning_text:
            r = m.reasoning.reasoning_text
            item["reasoning"] = (
                r if len(r) <= reasoning_chars else r[: reasoning_chars // 2] + "\n[...]\n" + r[-reasoning_chars // 2 :]
            )
        if m.tool_calls:
            item["calls"] = [
                {"tool": c.tool_name, "args": json.dumps(c.arguments, default=str)[:800]} for c in m.tool_calls
            ]
        if m.tool_call_results:
            item["results"] = [
                {
                    "tool": r.origin.tool_name,
                    "error": r.error,
                    "result": (r.result if isinstance(r.result, str) else str(r.result))[:result_chars],
                }
                for r in m.tool_call_results
            ]
        out.append(item)
    return out


@component
class CodeStep:
    """A pipeline step the optimizer wrote (`KIND = "step"`, `run(ctx)`), in the scanner's process."""

    def __init__(
        self,
        code: str,
        model: dict[str, Any] | None = None,
        scan: str = "",
        max_calls: int = 20,
        max_completion_tokens: int = 40_000,
        timeout_s: int = 900,
    ) -> None:
        self.code, self.model, self.scan = code, model or {}, scan
        self.max_calls, self.max_completion_tokens, self.timeout_s = max_calls, max_completion_tokens, timeout_s

    @component.output_types(findings=list[dict], record=dict)
    def run(self, findings: list[dict] | None = None) -> dict[str, Any]:
        """Run the step on the findings so far; returns the findings it passes on and its record."""
        ctx = context(self.scan)
        ctx.findings = _findings_in(findings, ctx)
        received = [dict(f) for f in ctx.findings]
        gateway = ModelGateway(self.model, self.max_calls, self.max_completion_tokens) if self.max_calls else None
        ctx.llm = Llm(gateway)
        started = time.monotonic()
        error = None
        try:
            module = load_code(Path(self.code))
            call_with_timeout(lambda: module.run(ctx), self.timeout_s)
        except Exception as exc:  # noqa: BLE001 - its input passes through unchanged; the record says why
            error = _error_text(exc)
            ctx.findings = received
        record = {
            "component": Path(self.code).stem,
            "ok": error is None,
            "error": error,
            "seconds": round(time.monotonic() - started, 2),
            "calls": gateway.calls if gateway else [],
            "input": len(received),
            "kept": len(ctx.findings),
            "received": compact(received),
            "passed": compact(ctx.findings),
        }
        return {"findings": [dict(f) for f in ctx.findings], "record": record}


# -- the candidate: checking and loading the pipeline YAML ---------------------------------------

ALLOWED = {SCAN_AGENT: ScanAgent, CODE_STEP: CodeStep, NORMALIZER: Normalizer}


def read_pipeline(directory: Path) -> dict[str, Any]:
    """A candidate's pipeline.yaml, parsed."""
    data = yaml.safe_load((Path(directory) / PIPELINE).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{PIPELINE} must be a mapping")  # noqa: TRY004 - callers report ValueErrors as problems
    return data


def _range_problems(where: str, kind: str, params: dict[str, Any]) -> list[str]:
    problems = []
    for key, (number, low, high) in RANGES.get(kind, {}).items():
        if key not in params:
            continue
        value = params[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or (number is int and not isinstance(value, int))
        ):
            problems.append(f"{where}: {key} must be {'an integer' if number is int else 'a number'}")
        elif not low <= value <= high:
            problems.append(f"{where}: {key}={value} is outside the allowed range [{low}, {high}]")
    return problems


def _component_problems(directory: Path, name: Any, spec: Any) -> tuple[str | None, list[str]]:
    """One component's type and what is wrong with it."""
    where = f"component `{name}`"
    problems = []
    if not isinstance(name, str) or not NAME.match(name):
        problems.append(f"{where}: names are lowercase letters, digits and underscores")
    if not isinstance(spec, dict) or not isinstance(spec.get("init_parameters", {}), dict):
        return None, [*problems, f"{where}: needs `type` and an `init_parameters` mapping"]
    kind = spec.get("type")
    if kind not in ALLOWED:
        return None, [*problems, f"{where}: type {kind!r} is not allowed; allowed: {sorted(ALLOWED)}"]
    params = spec.get("init_parameters") or {}
    accepted = set(inspect.signature(vars(ALLOWED[kind])["__init__"]).parameters) - {"self"}  # Haystack wraps the class
    if unknown := set(params) - accepted:
        problems.append(f"{where}: unknown init parameters {sorted(unknown)}")
    if injected := set(params) & set(INJECTED.get(kind, ())):
        problems.append(f"{where}: {sorted(injected)} are set by the experiment; remove them")
    for key, prefix in PATH_PARAMS.get(kind, {}).items():
        value = params.get(key)
        if (
            not isinstance(value, str)
            or not value.startswith(prefix)
            or ".." in value
            or not (directory / value).is_file()
        ):
            problems.append(f"{where}: {key} must be an existing file under {prefix} of the candidate (got {value!r})")
        elif kind == CODE_STEP:
            found, issues = check_code(directory / value)
            problems += issues
            if found and found != "step":
                problems.append(f'{where}: {value} has KIND {found!r}; a CodeStep runs KIND = "step" code')
    problems += _range_problems(where, kind, params)
    if kind == SCAN_AGENT:
        problems += _agent_problems(directory, where, params)
    return kind, problems


def _shape_problems(components: dict[str, Any], connections: list, count: dict[str, int]) -> list[str]:
    """What is wrong with the pipeline as a whole: its agent, its output and its connections."""
    problems = []
    if count.get(SCAN_AGENT) != 1 or (components.get("agent") or {}).get("type") != SCAN_AGENT:
        problems.append("exactly one ScanAgent, named `agent`")
    output = components.get("normalizer") or {}
    if output.get("type") != NORMALIZER:
        problems.append("the output component is a Normalizer named `normalizer`")
    elif (output.get("init_parameters") or {}).get("tau", 50) != 0:
        problems.append("normalizer.tau is fixed at 0 (no confidence threshold)")
    if count.get(CODE_STEP, 0) > MAX_STEPS:
        problems.append(f"at most {MAX_STEPS} CodeSteps")
    for c in connections:
        if not (isinstance(c, dict) and isinstance(c.get("sender"), str) and isinstance(c.get("receiver"), str)):
            problems.append("every connection is {sender: component.output, receiver: component.input}")
            break
        if c["sender"].split(".")[0] == "normalizer":
            problems.append("the normalizer is the output; nothing may follow it")
    return problems


def pipeline_problems(directory: Path, data: dict[str, Any] | None = None) -> list[str]:
    """Everything wrong with a candidate's pipeline YAML, without running anything it names. Empty when valid."""
    directory = Path(directory)
    try:
        data = data if data is not None else read_pipeline(directory)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [f"{PIPELINE} does not parse: {exc}"]
    problems: list[str] = []
    if extra := set(data) - TOP_LEVEL:
        problems.append(f"{PIPELINE}: unknown top-level keys {sorted(extra)}")
    components, connections = data.get("components"), data.get("connections")
    if not isinstance(components, dict) or not isinstance(connections, list):
        return [*problems, f"{PIPELINE} needs a `components` mapping and a `connections` list"]
    count: dict[str, int] = {}
    for name, spec in components.items():
        kind, issues = _component_problems(directory, name, spec)
        problems += issues
        if kind:
            count[kind] = count.get(kind, 0) + 1
    problems += _shape_problems(components, connections, count)
    if problems:
        return problems
    try:
        load_pipeline(directory, {"api_base_url": "http://127.0.0.1:1/v1", "model": "check"}, "check", data=data)
    except Exception as exc:  # Haystack's own checks: sockets, types, cycles
        problems.append(f"Haystack refuses the pipeline: {type(exc).__name__}: {str(exc)[:400]}")
    return problems


def _agent_problems(directory: Path, where: str, params: dict[str, Any]) -> list[str]:
    problems = []
    tools = params.get("tools") or []
    if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
        return [f"{where}: tools is a list of names: {list(BUILTIN_TOOLS)} and tools/<name>.py files"]
    if len(set(tools)) != len(tools):
        problems.append(f"{where}: tools lists a tool twice")
    for rel in tools:
        if rel in BUILTIN_TOOLS:
            continue
        if not rel.startswith("tools/") or ".." in rel or not (directory / rel).is_file():
            problems.append(
                f"{where}: tool {rel!r} is neither built in ({list(BUILTIN_TOOLS)}) nor an existing "
                "tools/<name>.py file"
            )
            continue
        found, issues = check_code(directory / rel)
        problems += issues
        if found and found != "tool":
            problems.append(f'{where}: {rel} has KIND {found!r}; the agent\'s tools have KIND = "tool"')
        elif Path(rel).stem in ("report_finding", *BUILTIN_TOOLS):
            problems.append(f"{where}: {rel}: the name {Path(rel).stem!r} is taken by a built-in tool")
    thinking, limit = params.get("thinking_budget", 1024), params.get("max_tokens", 4096)
    if isinstance(thinking, int) and isinstance(limit, int) and thinking and limit < thinking + 1024:
        problems.append(
            f"{where}: max_tokens must be at least thinking_budget + 1024 (room for the tool call or answer)"
        )
    for key in ("system_prompt", "user_prompt"):
        rel = params.get(key)
        if (
            isinstance(rel, str)
            and (directory / rel).is_file()
            and len((directory / rel).read_text(encoding="utf-8")) > MAX_PROMPT_CHARS
        ):
            problems.append(f"{where}: {rel} is longer than {MAX_PROMPT_CHARS} characters")
    rel = params.get("user_prompt")
    if isinstance(rel, str) and (directory / rel).is_file():
        import jinja2.meta

        try:
            used = jinja2.meta.find_undeclared_variables(
                jinja2.Environment(autoescape=False).parse((directory / rel).read_text(encoding="utf-8"))
            )
            if unknown := used - TEMPLATE_VARIABLES:
                problems.append(
                    f"{where}: {rel} uses unknown variables {sorted(unknown)}; available: {sorted(TEMPLATE_VARIABLES)}"
                )
        except jinja2.TemplateError as exc:
            problems.append(f"{where}: {rel} is not a valid Jinja2 template: {exc}")
    return problems


def _resolved(data: dict[str, Any], directory: Path, model: dict[str, Any], scan: str) -> dict[str, Any]:
    out = json.loads(json.dumps(data))
    model_kwargs = {
        k: model[k]
        for k in ("api_base_url", "model", "timeout_s", "max_retries", "temperature", "concurrency")
        if k in model
    }
    for spec in out["components"].values():
        kind, params = spec["type"], spec.setdefault("init_parameters", {})
        for key in PATH_PARAMS.get(kind, {}):
            params[key] = str((directory / params[key]).resolve())
        if kind == SCAN_AGENT:
            params["tools"] = [
                t if t in BUILTIN_TOOLS else str((directory / t).resolve()) for t in params.get("tools") or []
            ]
        if kind in INJECTED:
            params.update(model=model_kwargs, scan=scan)
    return out


def load_pipeline(directory: Path, model: dict[str, Any], scan: str, data: dict[str, Any] | None = None) -> Pipeline:
    """The candidate's Haystack pipeline, with the model and the scan filled in."""
    allow_deserialization_module("security_agent")
    return Pipeline.from_dict(
        _resolved(data if data is not None else read_pipeline(directory), Path(directory), model, scan)
    )


def candidate_fingerprint(directory: Path) -> str:
    """The candidate's identity for scan records: every file of it."""
    digest = hashlib.sha256(b"agent\0")
    for p in sorted(Path(directory).rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts:
            digest.update(p.relative_to(directory).as_posix().encode() + b"\0" + p.read_bytes())
    return digest.hexdigest()[:16]


# -- the scanner -----------------------------------------------------------------------------------


class AgentScanner:
    """Scans one staged repository with a candidate. Construction only checks the YAML; code runs in `scan`."""

    name = "agent"

    def __init__(self, candidate: str | Path, model_config: str | dict | None = None) -> None:
        directory = resolve(candidate)
        self.candidate_dir = directory.parent if directory.is_file() else directory
        self.data = read_pipeline(self.candidate_dir)
        if problems := pipeline_problems(self.candidate_dir, self.data):
            raise ValueError("invalid agent candidate: " + "; ".join(problems))
        model = model_config or "model.yaml"
        self.model = dict(model) if isinstance(model, dict) else load_yaml(model)
        self.fingerprint = candidate_fingerprint(self.candidate_dir)

    def describe(self) -> dict[str, Any]:
        """Everything that determines the scanner's behaviour, for the run manifest."""
        return {
            "name": self.name,
            "candidate": str(self.candidate_dir),
            "pipeline": self.data,
            "files_sha256": {
                p.relative_to(self.candidate_dir).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()[:16]
                for p in sorted(self.candidate_dir.rglob("*"))
                if p.is_file() and "__pycache__" not in p.parts
            },
            "fingerprint": self.fingerprint,
            "model": {k: self.model.get(k) for k in ("api_base_url", "model")},
        }

    def scan(self, repo: StagedRepo) -> ScanResult:
        """Scan one staged repository."""
        started = time.monotonic()
        root, files = str(repo.root), list(repo.files)
        key = uuid.uuid4().hex
        _CONTEXTS[key] = ScanContext(root, files)
        try:
            pipe = load_pipeline(self.candidate_dir, self.model, key, data=self.data)
            names = list(self.data["components"])
            fed = {c["receiver"].split(".")[0] for c in self.data["connections"]}
            data: dict[str, dict[str, Any]] = {
                name: {"findings": []}
                for name in names
                if self.data["components"][name]["type"] != NORMALIZER and name not in fed
            }
            data["normalizer"] = {"root": root, "files": files}
            out = pipe.run(data, include_outputs_from=set(names))
        finally:
            _CONTEXTS.pop(key, None)
        agent = out["agent"]["record"]
        steps = [out[n]["record"] for n in names if self.data["components"][n]["type"] == CODE_STEP and n in out]
        findings = [Finding(**{k: f.get(k) for k in FINDING_KEYS}) for f in out["normalizer"]["findings"]]
        calls = [
            c
            for c in agent["calls"] + agent["code_calls"] + [c for s in steps for c in s.get("calls", [])]
            if "error" not in c
        ]
        cost = Cost(
            seconds=round(time.monotonic() - started, 3),
            prompt_tokens=sum(int(c.get("prompt_tokens", 0)) for c in calls),
            completion_tokens=sum(int(c.get("completion_tokens", 0)) for c in calls),
            calls=len(calls),
        )
        # Only a model-server outage makes a scan incomplete: the candidate's own limits are its choice.
        outage = agent["outage"] or any(c.get("outage") for s in steps for c in s.get("calls", []))
        record = {
            "agent": agent,
            "components": steps,
            "candidates": agent["reported"],  # what the agent reported, before later steps (the digests compare)
            "normalize": out["normalizer"]["stats"],
        }
        return ScanResult(
            findings=findings,
            coverage=Coverage(files=len(files), reviewed=len({r["path"] for r in agent["reads"]}), skipped=[]),
            cost=cost,
            complete=not outage,
            error=(f"model-server outage: {agent['stop']}" if outage else None),
            record=record,
        )


def make_scanner(candidate: str | Path, model_config: str | dict | None = None) -> AgentScanner:
    """An `AgentScanner` for a candidate."""
    return AgentScanner(candidate, model_config=model_config)


# -- the optimizer's contract for agent candidates ------------------------------------------------

FIXTURE_DIR = Path(__file__).parent / "fixture"  # a tiny repository the contract test runs the code on


def fixture_files() -> list[str]:
    """The fixture repository's files."""
    return sorted(
        p.relative_to(FIXTURE_DIR).as_posix()
        for p in FIXTURE_DIR.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    )


FIXTURE_FINDINGS = [
    {
        "path": "src/fixture_components/fetcher.py",
        "line_start": 22,
        "line_end": 22,
        "cwe": "CWE-918",
        "title": "URL fetched unchecked",
        "confidence": 70,
        "severity": "high",
        "source": "path",
        "sink": "urlopen",
        "missing_control": "no host check",
    },
    {
        "path": "src/fixture_components/fetcher.py",
        "line_start": 27,
        "line_end": 27,
        "cwe": "CWE-918",
        "title": "checked fetch",
        "confidence": 30,
        "severity": "low",
        "source": "",
        "sink": "",
        "missing_control": "",
    },
]
CONTRACT_TIMEOUT_S = 60


def _tool_contract(path: Path, rel: str) -> list[str]:
    """One of the agent's tools on the fixture repository."""
    from haystack.tools import Tool

    ctx = ScanContext(str(FIXTURE_DIR), fixture_files())
    ctx.llm = Llm(StubGateway())
    try:
        module = call_with_timeout(lambda: load_code(path), 20)
        description = getattr(module, "DESCRIPTION", None)
        if not isinstance(description, str) or not description.strip() or len(description) > MAX_DESCRIPTION_CHARS:
            return [f"{rel}: needs DESCRIPTION, a string of at most 3,000 characters that tells the agent what it does"]
        parameters = getattr(module, "PARAMETERS", None)
        if not isinstance(parameters, dict) or parameters.get("type") != "object":
            return [
                f"{rel}: needs PARAMETERS, a JSON schema of type object (its properties are run's keyword arguments)"
            ]
        Tool(name=path.stem, description=description, parameters=parameters, function=lambda **_: "")
        signature = inspect.signature(module.run).parameters
        has_kwargs = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in signature.values())
        missing = set(parameters.get("properties") or {}) - (set(signature) - {"ctx"})
        if missing and not has_kwargs:
            return [f"{rel}: PARAMETERS has properties {sorted(missing)} that run(ctx, ...) does not accept"]
        example = getattr(module, "EXAMPLE", None)
        if example is not None:
            if not isinstance(example, dict):
                return [f"{rel}: EXAMPLE must be a dict of arguments"]
            value = call_with_timeout(lambda: module.run(ctx, **example), CONTRACT_TIMEOUT_S)
            if not isinstance(value, str):
                json.dumps(value)
    except Exception as exc:  # reported to the optimizer
        return [
            f"{rel} failed on the fixture repository (the model answered every request with an error; a tool "
            f"must cope): {_error_text(exc)[-700:]}"
        ]
    return []


def _step_contract(path: Path, rel: str, name: str) -> list[str]:
    """One step on the fixture repository, with two findings."""
    ctx = ScanContext(str(FIXTURE_DIR), fixture_files())
    ctx.findings = _findings_in(FIXTURE_FINDINGS, ctx)
    ctx.llm = Llm(StubGateway())
    try:
        module = call_with_timeout(lambda: load_code(path), 20)
        call_with_timeout(lambda: module.run(ctx), CONTRACT_TIMEOUT_S)
        if not isinstance(ctx.findings, list) or any(not isinstance(f, dict) or ctx._problem(f) for f in ctx.findings):
            return [
                f"{rel} (step `{name}`): ctx.findings must stay a list of valid findings; change it with "
                "ctx.report, ctx.retract and ctx.update"
            ]
    except Exception as exc:  # reported to the optimizer
        return [
            f"{rel} (step `{name}`) failed on the fixture repository (the model answered every request with an "
            f"error; a step must cope): {_error_text(exc)[-700:]}"
        ]
    return []


def contract_test(directory: Path) -> list[str]:
    """
    Run the candidate's code once on the fixture repository; problems, or empty.

    The model answers every request with an error (as when the budget is spent). Tools are imported and run with their
    `EXAMPLE` arguments if they define them; steps get two findings and must leave a valid list of findings.
    """
    directory = Path(directory)
    data = read_pipeline(directory)
    agent = data["components"]["agent"].get("init_parameters") or {}
    problems = []
    for rel in [t for t in agent.get("tools") or [] if t not in BUILTIN_TOOLS]:
        problems += _tool_contract(directory / rel, rel)
    for name, spec in data["components"].items():
        if spec.get("type") == CODE_STEP:
            rel = str((spec.get("init_parameters") or {}).get("code"))
            problems += _step_contract(directory / rel, rel, name)
    return problems


def check_candidate(directory: Path) -> list[str]:
    """Every way a candidate breaks the contract, without running its code (`contract_test` does that)."""
    from security_agent.optimize import candidate as cand

    directory = Path(directory)
    mine = cand.files(directory)
    try:
        data = read_pipeline(directory)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [f"{PIPELINE} does not parse: {exc}"]
    errors = pipeline_problems(directory, data)
    if errors:
        return errors
    components = data["components"]
    agent = components["agent"].get("init_parameters") or {}
    used = {agent.get("system_prompt"), agent.get("user_prompt")} | {
        t for t in agent.get("tools") or [] if t not in BUILTIN_TOOLS
    }
    used |= {(s.get("init_parameters") or {}).get("code") for s in components.values() if s.get("type") == CODE_STEP}
    code = [f for f in mine if f.startswith("tools/")]
    if strays := sorted(f for f in mine if f != PIPELINE and f not in used):
        errors.append(f"files the pipeline does not use (delete them, or use them): {strays}")
    if bad := sorted(f for f in code if not re.fullmatch(r"tools/[a-z][a-z0-9_]{1,40}\.py", f)):
        errors.append(f"code files are tools/<name>.py with a lowercase name: {bad}")
    if len(code) > MAX_CODE_FILES:
        errors.append(f"at most {MAX_CODE_FILES} code files")
    names = [Path(t).stem for t in agent.get("tools") or [] if t not in BUILTIN_TOOLS]
    if len(set(names)) != len(names):
        errors.append("two tools have the same name")
    return errors


def describe_contract() -> str:
    """The contract as text, for the optimizer's system prompt."""
    lines = ["Allowed component types (anything else is refused):"]
    for kind, rules in RANGES.items():
        parts = [f"{k} ({r[1]}..{r[2]})" for k, r in rules.items()]
        lines.append(f"- `{kind}`: " + ", ".join(parts))
    lines += [
        f"- Exactly one `{SCAN_AGENT}`, named `agent`. Its `system_prompt` and `user_prompt` are files under "
        f"`prompts/`; the user prompt is a Jinja2 template that may use {sorted(TEMPLATE_VARIABLES)}. Prompt files: "
        f"at most {MAX_PROMPT_CHARS:,} characters.",
        f"- `agent.tools` lists the built-in tools it gets ({', '.join(BUILTIN_TOOLS)}) and your tools "
        '(`tools/<name>.py`, KIND = "tool"). report_finding is always on and cannot be replaced.',
        f'- At most {MAX_STEPS} `{CODE_STEP}`s (KIND = "step"), connected through their `findings` sockets before or '
        "after the agent.",
        "- The output is a Normalizer named `normalizer` with `tau: 0`, fed by the last step's (or the agent's) "
        "`findings`; nothing may follow it.",
        "- Set by the experiment, not in the YAML: `model` and `scan`.",
        f"- Code: at most {MAX_CODE_FILES} files of at most {MAX_CODE_LINES} lines; every file in the candidate must "
        "be used. Imports are limited to the standard library's text and analysis modules (re, ast, json, collections, "
        "itertools, functools, difflib, math, ...); no os, sys, pathlib, io, network or subprocess modules, and no "
        "open(), eval(), exec() or getattr(). Read the repository through ctx.repo.",
        f"- A model call from your code: at most {CALL_LIMITS['max_tokens']:,} output tokens, a thinking budget of at "
        f"most {CALL_LIMITS['thinking']:,} and {CALL_LIMITS['prompt_chars']:,} characters of prompt.",
    ]
    return "\n".join(lines)
