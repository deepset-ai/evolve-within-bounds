# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Loading an agent file, and the two fallbacks for an answer that went missing.

An agent is a serialized Haystack `Agent` (agents/primevul/*/agent.yaml). Two things can leave a task without an
answer for reasons that are not the model's verdict, and both are handled here:

- **An empty reply.** A reasoning model can spend its whole reply thinking and return no text and no tool call. The
  `Agent` loop does not exit on such a reply, and the next request ends in two assistant messages, which some servers
  reject. `guard_empty_replies` gives every such reply the JSON object from its reasoning, or a marker that scores as
  a parse error.
- **No final answer.** An agent that is still calling tools when its step budget runs out ends without a verdict.
  `force_final_answer` asks once more, with no tools, for the answer from what it has gathered.

The thinking budget is set per request (`with_thinking_budget`), so the agent files stay as they ran.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import yaml

from security_agent.primevul.verdict import extract_json_object

# How the agents ran: Flash-Next with at most this many reasoning tokens per reply.
THINKING_BUDGET = 2048

FINAL_ANSWER_PROMPT = (
    "Your step budget is exhausted and no further tool calls will be executed. Give your final "
    "answer now, in exactly the format your instructions require, using what you have gathered."
)
JSON_ONLY_PROMPT = "Reply with the JSON object only, no reasoning."
EMPTY_REPLY_TEXT = "(the model returned no text)"


def agent_file(path: Path) -> Path:
    """An agent's YAML file: the path itself, or `agent.yaml` in that directory."""
    return path / "agent.yaml" if path.is_dir() else path


def load_config(path: Path) -> dict[str, Any]:
    """The serialized agent at `path` (a file, or a directory with `agent.yaml`)."""
    with agent_file(path).open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    if not isinstance(config, dict) or not isinstance(config.get("init_parameters"), dict):
        raise ValueError(f"{agent_file(path)} is not a serialized Haystack Agent")  # noqa: TRY004 - a bad file
    return config


def configuration_id(config: dict[str, Any]) -> str:
    """An agent's identity by parsed content, so comments, whitespace and key order do not count."""
    return hashlib.sha256(json.dumps(config, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


def with_thinking_budget(config: dict[str, Any], budget: int | None) -> dict[str, Any]:
    """
    A copy of `config` whose chat generator caps the model's reasoning at `budget` tokens per reply.

    vLLM takes the cap per request (`thinking_token_budget`). `None` leaves the config as it is.
    """
    config = copy.deepcopy(config)
    if budget is None:
        return config
    generator = config["init_parameters"]["chat_generator"]["init_parameters"]
    kwargs = generator.get("generation_kwargs") or {}
    kwargs["extra_body"] = {**(kwargs.get("extra_body") or {}), "thinking_token_budget": int(budget)}
    generator["generation_kwargs"] = kwargs
    return config


def load_agent(config: dict[str, Any]) -> Any:
    """Deserialize an agent, with this package allowed as a component source and empty replies guarded."""
    from haystack.components.agents import Agent
    from haystack.core.serialization_security import allow_deserialization_module

    # The agent files read their API key from OPENAI_API_KEY; the local model server does not check it.
    os.environ.setdefault("OPENAI_API_KEY", "EMPTY")
    allow_deserialization_module("security_agent")
    return guard_empty_replies(Agent.from_dict(copy.deepcopy(config)))


def _json_from_reasoning(reply: Any) -> str | None:
    """The last JSON object in a reply's reasoning, for a reply whose visible text is empty."""
    reasoning = getattr(reply, "reasoning", None)
    text = getattr(reasoning, "reasoning_text", None) if reasoning is not None else None
    return extract_json_object(text) if text else None


def guard_empty_replies(agent: Any) -> Any:
    """Make every reply of the agent's chat generator carry text or a tool call, so its loop can always exit."""
    from haystack.dataclasses import ChatMessage

    generator = getattr(agent, "chat_generator", None)
    if generator is None or getattr(generator.run, "_guards_empty_replies", False):
        return agent
    original = generator.run

    def run(*args: Any, **kwargs: Any) -> dict[str, Any]:
        out = original(*args, **kwargs)
        replies = out.get("replies") or []
        for i, reply in enumerate(replies):
            if (getattr(reply, "text", None) or "").strip() or getattr(reply, "tool_calls", None):
                continue
            replies[i] = ChatMessage.from_assistant(
                _json_from_reasoning(reply) or EMPTY_REPLY_TEXT,
                meta=dict(getattr(reply, "meta", None) or {}),
                reasoning=getattr(reply, "reasoning", None),
            )
        return out

    run._guards_empty_replies = True  # type: ignore[attr-defined]
    generator.run = run
    return agent


def force_final_answer(agent: Any, out: dict[str, Any], prompt: str = FINAL_ANSWER_PROMPT) -> dict[str, Any]:
    """
    One call without tools that asks for the final answer; `out` with the exchange appended.

    A reply with no text gets the JSON object from its reasoning, or else one more request for the JSON alone. A failed
    call leaves `out` as it was.
    """
    from haystack.dataclasses import ChatMessage

    messages = list(out.get("messages") or [])
    nudge = ChatMessage.from_user(prompt)
    try:
        replies = agent.chat_generator.run(messages=[*messages, nudge], tools=None).get("replies") or []
    except Exception:
        return out
    if not replies:
        return out
    reply = replies[0]
    if not (reply.text or "").strip():
        salvaged = _json_from_reasoning(reply)
        if salvaged is None:
            try:
                retry = (
                    agent.chat_generator.run(
                        messages=[*messages, nudge, ChatMessage.from_user(JSON_ONLY_PROMPT)], tools=None
                    ).get("replies")
                    or []
                )
            except Exception:
                retry = []
            if retry and (retry[0].text or "").strip():
                reply = retry[0]
            elif retry:
                salvaged = _json_from_reasoning(retry[0])
        if salvaged is not None:
            reply = ChatMessage.from_assistant(salvaged)
    return {**out, "messages": [*messages, nudge, reply], "last_message": reply, "forced_final_answer": True}


def usage(messages: Any) -> dict[str, int]:
    """Tokens and calls of the assistant replies in `messages`; cached: prompt tokens from the prefix cache."""
    total = {"prompt_tokens": 0, "completion_tokens": 0, "cached_tokens": 0, "calls": 0}
    for message in messages if isinstance(messages, list) else []:
        if getattr(message.role, "value", message.role) != "assistant":
            continue
        counts = (message.meta or {}).get("usage") or {}
        total["prompt_tokens"] += int(counts.get("prompt_tokens") or 0)
        total["completion_tokens"] += int(counts.get("completion_tokens") or 0)
        total["cached_tokens"] += int((counts.get("prompt_tokens_details") or {}).get("cached_tokens") or 0)
        total["calls"] += 1
    return total


def _json_text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def openai_messages(messages: Any) -> list[dict[str, Any]]:
    """Haystack chat messages in the OpenAI format: role, content, tool calls, and tool results by call id."""
    if not isinstance(messages, list):
        return []
    converted: list[dict[str, Any]] = []
    for message in messages:
        role = getattr(message.role, "value", str(message.role))
        if message.tool_call_results:
            for index, result in enumerate(message.tool_call_results):
                origin = result.origin
                tool_message: dict[str, Any] = {
                    "role": "tool",
                    "tool_call_id": str(origin.id or (origin.extra or {}).get("call_id") or f"call_{index}"),
                    "content": result.result
                    if isinstance(result.result, str)
                    else "\n".join(getattr(part, "text", "") for part in result.result),
                }
                if origin.tool_name:
                    tool_message["name"] = origin.tool_name
                if result.error:
                    tool_message["error"] = True
                converted.append(tool_message)
            continue
        texts = message.texts
        calls = message.tool_calls
        entry: dict[str, Any] = {"role": role, "content": "\n".join(texts) if texts else (None if calls else "")}
        if calls:
            entry["tool_calls"] = [
                {
                    "id": str(call.id or (call.extra or {}).get("call_id") or f"call_{index}"),
                    "type": "function",
                    "function": {"name": call.tool_name, "arguments": _json_text(call.arguments)},
                }
                for index, call in enumerate(calls)
            ]
        converted.append(entry)
    return converted
