# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The optimizer: a Haystack Agent on the same model server that edits the draft through the workspace tools.

A turn ends when the agent calls `submit_candidate` or `finish`. When it stops otherwise (a text-only reply, a
malformed tool call, the step budget), it is nudged up to `nudges` times with the conversation so far. If it still has
not submitted but left a valid edited draft, the draft is auto-submitted; the rationale records this. The turn's
messages are saved: they are the record of why a candidate looks the way it does.
"""

from __future__ import annotations

import dataclasses
import functools
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from haystack.components.agents import Agent
from haystack.dataclasses import ChatMessage

from security_agent.generator import call_waiting, make_generator, malformed_tool_calls
from security_agent.optimize.workspace import Submission, Workspace

NUDGE = (
    "Your turn ended without submit_candidate or finish. Continue from the current draft (revision {revision}): "
    "edit, validate_candidate, then submit_candidate, or call finish with a reason."
)
MALFORMED = " Your last tool call could not be parsed (invalid JSON arguments); make smaller edits with shorter text."
REMINDER = (
    "[{left} of your {total} steps in this turn are left. Bring the draft to a valid state: validate_candidate, then "
    "submit_candidate with the best valid version you have. Do not start new work.]"
)
EMPTY_REPLY = "(the model returned no text)"

Proposer = Callable[[Workspace, list[str], Path], tuple[Submission | None, dict[str, Any]]]
# Called after each of the optimizer's tool calls with the tool's name, its arguments and its result (or the error).
ToolObserver = Callable[[str, dict[str, Any], str], None]


def step_reminder(max_steps: int) -> Any:
    """
    A hook that reminds the optimizer to submit when its turn is running out of steps.

    Before the model call with a quarter of the turn's steps left, and again with a twelfth left (15 and 5 of 60):
    long turns otherwise run out of steps with valid work unsubmitted.
    """
    from haystack.components.agents.state import State
    from haystack.hooks import hook

    marks = sorted({max(1, max_steps // 4), max(1, max_steps // 12)}, reverse=True)

    def remind(state: Any) -> None:
        left = max_steps - int(state.get("step_count") or 0)
        if left in marks:
            state.set("messages", [ChatMessage.from_user(REMINDER.format(left=left, total=max_steps))])

    remind.__annotations__ = {
        "state": State,
        "return": None,
    }  # Haystack checks the type; this module's annotations are strings
    return hook(remind)


def guard_empty_replies(agent: Agent) -> Agent:
    """Give a reply with neither text nor a tool call a placeholder text, so the Agent loop can always exit."""
    generator = agent.chat_generator
    original = generator.run

    def run(*args: Any, **kwargs: Any) -> dict:
        out = original(*args, **kwargs)
        for i, reply in enumerate(out.get("replies") or []):
            if not (reply.text or "").strip() and not reply.tool_calls:
                out["replies"][i] = ChatMessage.from_assistant(
                    EMPTY_REPLY, meta=dict(reply.meta or {}), reasoning=reply.reasoning
                )
        return out

    generator.run = run  # type: ignore[method-assign]
    return agent


class _Refusal(ValueError):
    """Raised by submit/finish on refusal, so the Agent sees a tool error and does not take it as its exit."""


def _exit_tools(workspace: Workspace) -> list:
    tools = []
    for tool in workspace.tools():
        if tool.name in ("submit_candidate", "finish"):
            original = tool.function

            def guarded(*args: Any, _f: Callable[..., str] = original, **kwargs: Any) -> str:  # type: ignore[assignment]
                result = _f(*args, **kwargs)
                if not json.loads(result).get("ok"):
                    raise _Refusal(result)
                return result

            tool = dataclasses.replace(tool, function=guarded)
        tools.append(tool)
    return tools


def _observed(tools: list, observer: ToolObserver | None) -> list:
    """The tools, each reporting its calls to `observer` (refusals and errors too)."""
    if observer is None:
        return tools
    observed = []
    for tool in tools:

        def call(*args: Any, _f: Callable[..., str] = tool.function, _name: str = tool.name, **kwargs: Any) -> str:
            try:
                result = _f(*args, **kwargs)
            except Exception as exc:
                observer(_name, kwargs, f"{type(exc).__name__}: {exc}")
                raise
            observer(_name, kwargs, result)
            return result

        observed.append(dataclasses.replace(tool, function=call))
    return observed


def agent_proposer(
    model: dict[str, Any], settings: dict[str, Any], system: str, observer: ToolObserver | None = None
) -> Proposer:
    """
    The optimizer: a Haystack Agent with the workspace's tools.

    :param model: the model server's settings.
    :param settings: the `proposer` section of the loop's config.
    :param system: its system prompt, from the task.
    :param observer: called after each tool call, e.g. to show the turn as it happens.
    """

    def propose(workspace: Workspace, context: list[str], trajectory: Path) -> tuple[Submission | None, dict[str, Any]]:
        started = time.monotonic()
        generator = make_generator(
            model,
            max_tokens=int(settings["max_tokens"]),
            thinking_budget=int(settings["thinking_budget"]),
            temperature=float(settings["temperature"]),
        )
        hooks: Any = (
            {"before_llm": [step_reminder(int(settings["max_steps"]))]} if settings.get("step_reminder") else None
        )
        agent = guard_empty_replies(
            Agent(
                hooks=hooks,
                chat_generator=generator,
                tools=_observed(_exit_tools(workspace), observer),
                system_prompt=system,
                exit_conditions=["submit_candidate", "finish", "text"],
                max_agent_steps=int(settings["max_steps"]),
                tool_concurrency_limit=1,
                required_variables=None,
            )
        )
        agent.warm_up()
        messages = [ChatMessage.from_user(part) for part in context if part.strip()]
        info: dict[str, Any] = {
            "steps": 0,
            "nudges": 0,
            "malformed_tool_calls": 0,
            "tool_calls": [],
            "prompt_tokens": 0,
            "completion_tokens": 0,
        }
        transcript: list[ChatMessage] = []
        for attempt in range(int(settings.get("nudges", 2)) + 1):
            try:
                out = call_waiting(
                    functools.partial(agent.run, messages=messages),
                    model["api_base_url"],
                    model["model"],
                    on_wait=lambda: info.__setitem__("server_waits", info.get("server_waits", 0) + 1),
                )
            except Exception as exc:  # noqa: BLE001 - a failed turn is recorded; the loop decides what to do
                info["error"] = f"{type(exc).__name__}: {exc}"[:500]
                break
            produced = [m for m in out.get("messages") or [] if not m.is_from("system")]
            new = produced[len(messages) :]
            transcript += new
            assistant = [m for m in new if m.is_from("assistant")]
            info["steps"] += len(assistant)
            info["malformed_tool_calls"] += sum(1 for m in assistant if malformed_tool_calls(m))
            info["tool_calls"] += [tc.tool_name for m in assistant for tc in (m.tool_calls or [])]
            info["prompt_tokens"] += sum(int((m.meta.get("usage") or {}).get("prompt_tokens") or 0) for m in assistant)
            info["completion_tokens"] += sum(
                int((m.meta.get("usage") or {}).get("completion_tokens") or 0) for m in assistant
            )
            if workspace.submitted or workspace.finish_reason or attempt == int(settings.get("nudges", 2)):
                break
            info["nudges"] += 1
            nudge = NUDGE.format(revision=workspace.revision) + (
                MALFORMED if assistant and malformed_tool_calls(assistant[-1]) else ""
            )
            messages = produced + [ChatMessage.from_user(nudge)]
            transcript.append(messages[-1])
        submission = workspace.submitted
        if submission is None and workspace.finish_reason is None:
            last = next((m.text for m in reversed(transcript) if m.is_from("assistant") and m.text), "") or ""
            submission = workspace.auto_submit(last)
        info.update(
            seconds=round(time.monotonic() - started, 1),
            submitted=submission.candidate_id if submission else None,
            auto_submitted=bool(submission and submission.auto),
            finish_reason=workspace.finish_reason,
            edits=workspace.edits,
        )
        trajectory.parent.mkdir(parents=True, exist_ok=True)
        trajectory.write_text(
            json.dumps(
                {"info": info, "context": context, "messages": [m.to_dict() for m in transcript]}, indent=1, default=str
            ),
            encoding="utf-8",
        )
        return submission, info

    return propose
