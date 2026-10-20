# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Running an agent over the tasks, resumably, and scoring the pairs.

Each worker thread builds its own agent and judges one function per call. A task whose answer has no verdict gets one
more request for the final answer (`agent.force_final_answer`). Every finished task is written to the cache file, so an
interrupted measurement resumes where it stopped.

A task's record keeps its answer, verdict, steps and seconds, the tokens it cost (the agent's calls and the
knowledge-base sub-agent's), and a compressed trajectory: each tool call with the head of its arguments and result,
and what the sub-agent did with it. The records are for the loop's digests and for budget summaries (`tool_usage`);
the commands print aggregates only.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from security_agent.primevul import agent as agents
from security_agent.primevul.scoring import PairMetrics, aggregate
from security_agent.primevul.tasks import Task, pair_up
from security_agent.primevul.verdict import parse_verdict

MAX_TOOL_ARG_CHARS = 200
MAX_TOOL_RESULT_CHARS = 400
MAX_SUB_AGENT_CALLS = 4
TOOL_ERROR_MARKS = (
    "(error",
    "Failed to invoke",
    "No matching information",
    "No knowledge-base results",
    "Error:",
    "tool error:",
)


def compress_trajectory(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    An agent's steps, short: each tool call with the head of its arguments and result, and each reply's length.

    A result that reads as an error or an empty answer is flagged `failed`. Takes OpenAI-format messages
    (`agent.openai_messages`); the user turn is skipped.
    """
    steps: list[dict[str, Any]] = []
    pending: dict[str, str] = {}
    for msg in messages:
        role = msg.get("role")
        if role == "assistant":
            for call in msg.get("tool_calls") or []:
                fn = call.get("function") or {}
                args = fn.get("arguments") or ""
                args = args if isinstance(args, str) else json.dumps(args)
                pending[str(call.get("id"))] = fn.get("name") or "?"
                steps.append({"tool": fn.get("name") or "?", "args": args[:MAX_TOOL_ARG_CHARS]})
            if msg.get("content"):
                steps.append({"reply_chars": len(msg["content"])})
        elif role == "tool":
            text = msg.get("content") or ""
            text = text if isinstance(text, str) else json.dumps(text)
            step: dict[str, Any] = {
                "tool": pending.pop(str(msg.get("tool_call_id")), "?"),
                "result": text[:MAX_TOOL_RESULT_CHARS],
            }
            if any(mark in text[:300] for mark in TOOL_ERROR_MARKS):
                step["failed"] = True
            for prev in reversed(steps):
                if "args" in prev and "result" not in prev and prev["tool"] == step["tool"]:
                    prev.update(result=step["result"], **({"failed": True} if step.get("failed") else {}))
                    break
            else:
                steps.append(step)
    return steps


def attach_sub_agent_traces(
    steps: list[dict[str, Any]],
    take: Callable[[str], dict[str, Any] | None],
    messages: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    For each knowledge-base call: the sub-agent's own tool calls, documents kept, the head of its answer, seconds.

    A trace is found by its query. `messages` (the OpenAI-format messages the steps were compressed from) give the
    calls' full arguments: a step keeps only their head.
    """
    full = [
        (call.get("function") or {}).get("arguments") or ""
        for msg in messages or []
        if msg.get("role") == "assistant"
        for call in msg.get("tool_calls") or []
    ]
    for index, step in enumerate(s for s in steps if "args" in s):
        args = full[index] if index < len(full) else step["args"]
        args = args if isinstance(args, str) else json.dumps(args)
        try:
            query = json.loads(args).get("query") if args.startswith("{") else None
        except (json.JSONDecodeError, AttributeError):
            query = None
        if not isinstance(query, str):
            continue
        trace = take(query.strip())
        if trace is None:
            continue
        sub: dict[str, Any] = {"seconds": trace.get("seconds"), "usage": trace.get("usage")}
        if trace.get("error"):
            sub["error"] = trace["error"]
        else:
            calls = [c for c in compress_trajectory(trace.get("messages") or []) if "args" in c]
            sub.update(
                steps=trace.get("steps"),
                documents=trace.get("documents"),
                answer=(trace.get("answer") or "")[:300],
                calls=[
                    {k: (v[:160] if isinstance(v, str) else v) for k, v in c.items()}
                    for c in calls[:MAX_SUB_AGENT_CALLS]
                ],
            )
            if len(calls) > MAX_SUB_AGENT_CALLS:
                sub["calls_omitted"] = len(calls) - MAX_SUB_AGENT_CALLS
        step["sub_agent"] = sub
    return steps


def _count(items: list[str]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])


def tool_usage(records: dict[str, dict[str, Any]], config: dict[str, Any] | None = None) -> dict[str, Any]:
    """How an agent spent its budget: tool calls and their failures, step-cap hits, forced answers, time."""
    trajectories = {tid: r.get("trajectory") or [] for tid, r in records.items()}
    calls = [step for steps in trajectories.values() for step in steps if "args" in step]
    failed = [c for c in calls if c.get("failed")]
    sub_calls = [c for step in calls for c in (step.get("sub_agent") or {}).get("calls", [])]
    sub_failed = [c for c in sub_calls if c.get("failed")]
    by_tool = dict(_count([c["tool"] for c in calls]))
    cap = (config or {}).get("init_parameters", {}).get("max_agent_steps")
    steps: list[int] = [r["steps"] for r in records.values() if isinstance(r.get("steps"), int)]
    secs = sorted(r["seconds"] for r in records.values() if r.get("seconds"))
    return {
        "tasks": len(records),
        "tasks_with_a_tool_call": sum(1 for t in trajectories.values() if any("args" in s for s in t)),
        "tool_calls": len(calls),
        "calls_by_tool": by_tool,
        "failed_tool_calls": len(failed),
        "failed_by_tool": dict(_count([c["tool"] for c in failed])),
        "tasks_calling_tool": {
            name: sum(1 for t in trajectories.values() if any(s.get("tool") == name and "args" in s for s in t))
            for name in by_tool
        },
        "most_common_failures": _count([(c.get("result") or "")[:120] for c in failed])[:5],
        "sub_agent": {
            "calls": len(sub_calls),
            "failed_calls": len(sub_failed),
            "empty_answers": sum(1 for step in calls if (step.get("sub_agent") or {}).get("documents") == 0),
            "most_common_failures": _count([(c.get("result") or "")[:120] for c in sub_failed])[:5],
        }
        if sub_calls
        else None,
        "tasks_at_step_cap": sum(1 for n in steps if cap and n >= cap),
        "max_agent_steps": cap,
        "mean_steps": round(sum(steps) / len(steps), 2) if steps else None,
        "forced_final_answers": sum(1 for r in records.values() if r.get("forced")),
        "errors": sum(1 for r in records.values() if r.get("error")),
        "median_seconds_per_task": secs[len(secs) // 2] if secs else None,
    }


def _sub_agent_trace_taker() -> Callable[[str], dict[str, Any] | None]:
    """The knowledge-base tool's trace sink, emptied."""
    try:
        from security_agent.knowledge_base.search import SUB_AGENT_TRACES
    except ImportError:  # the knowledge-base dependencies are not installed
        return lambda _query: None
    SUB_AGENT_TRACES.clear()
    return SUB_AGENT_TRACES.take


def record_usage(messages: list[Any] | None, trajectory: list[dict[str, Any]]) -> dict[str, int]:
    """The tokens and calls one function cost: the agent's replies, and the sub-agent's in each knowledge-base call."""
    total = agents.usage(messages)
    for step in trajectory:
        for key, value in ((step.get("sub_agent") or {}).get("usage") or {}).items():
            total[key] = total.get(key, 0) + int(value or 0)
    return total


def generation_stats(messages: list[Any] | None) -> dict[str, Any]:
    """Completion tokens of each assistant reply (thinking included), and how many replies stopped at max_tokens."""
    replies = [m for m in messages or [] if getattr(m.role, "value", m.role) == "assistant"]
    return {
        "completion_tokens": [((m.meta or {}).get("usage") or {}).get("completion_tokens") for m in replies],
        "length_stops": sum(1 for m in replies if (m.meta or {}).get("finish_reason") == "length"),
    }


def measure(
    config: dict[str, Any],
    tasks: list[Task],
    *,
    concurrency: int = 4,
    log: Callable[[str], None] = print,
    cache: Path | None = None,
    load_agent: Callable[[dict[str, Any]], Any] = agents.load_agent,
) -> tuple[PairMetrics, dict[str, dict[str, Any]]]:
    """Run the agent on every task not yet in `cache`, then score the pairs. Returns the metrics and the records."""
    from haystack.dataclasses import ChatMessage

    take_sub_agent_trace = _sub_agent_trace_taker()
    records: dict[str, dict[str, Any]] = {}
    if cache and cache.exists():
        records = {r["task_id"]: r for r in json.loads(cache.read_text(encoding="utf-8"))}
    todo = [t for t in tasks if t.id not in records]
    started = time.monotonic()
    local = threading.local()

    def agent_for_thread() -> Any:
        agent = getattr(local, "agent", None)
        if agent is None:
            agent = load_agent(config)
            agent.warm_up()
            local.agent = agent
        return agent

    def run_one(task: Task) -> dict[str, Any]:
        t0 = time.monotonic()
        record: dict[str, Any] = {"task_id": task.id, "pair_id": task.gold.get("pair_id")}
        try:
            agent = agent_for_thread()
            out = agent.run(messages=[ChatMessage.from_user(task.question)])
            answer = out["last_message"].text or ""
            if parse_verdict(answer)["parse_error"]:
                out = agents.force_final_answer(agent, out)
                answer = out["last_message"].text or ""
                record["forced"] = True
            messages = agents.openai_messages(out.get("messages"))
            trajectory = attach_sub_agent_traces(compress_trajectory(messages), take_sub_agent_trace, messages)
            record.update(
                answer=answer,
                steps=out.get("step_count"),
                verdict=parse_verdict(answer),
                trajectory=trajectory,
                generation=generation_stats(out.get("messages")),
                usage=record_usage(out.get("messages"), trajectory),
            )
        except Exception as exc:  # one task must not stop the measurement
            record.update(answer="", error=f"{type(exc).__name__}: {exc}", verdict={"parse_error": True})
        record["seconds"] = round(time.monotonic() - t0, 1)
        return record

    lock = threading.Lock()
    done = 0
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for record in pool.map(run_one, todo):
            with lock:
                records[record["task_id"]] = record
                done += 1
                if cache:
                    cache.parent.mkdir(parents=True, exist_ok=True)
                    cache.write_text(json.dumps(list(records.values()), default=str), encoding="utf-8")
                if done % 20 == 0 or done == len(todo):
                    log(f"    {done}/{len(todo)} tasks, {time.monotonic() - started:.0f}s")
    verdicts = {tid: r["verdict"] for tid, r in records.items()}
    metrics = aggregate(pair_up(tasks), verdicts, seconds=time.monotonic() - started)
    secs = sorted(r["seconds"] for r in records.values() if r.get("seconds"))
    metrics.median_task_seconds = secs[len(secs) // 2] if secs else 0.0
    return metrics, records
