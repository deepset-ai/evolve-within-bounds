# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json

from haystack.dataclasses import ChatMessage, ReasoningContent, ToolCall
from pv_helpers import write_benchmark

from security_agent.primevul import agent as agents
from security_agent.primevul.measure import attach_sub_agent_traces, compress_trajectory, measure, tool_usage
from security_agent.primevul.tasks import load_tasks

BENIGN = json.dumps({"is_vulnerable": False, "cwe": None, "vulnerable_lines": [], "rationale": "bounded"})
VULNERABLE = json.dumps({"is_vulnerable": True, "cwe": "CWE-787", "vulnerable_lines": [1], "rationale": "strcpy"})


class FakeGenerator:
    """Answers the forced-final-answer call."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = 0

    def run(self, messages, tools=None):
        self.calls += 1
        return {"replies": [self.replies.pop(0)]}


class FakeAgent:
    """Calls the knowledge-base tool once, then answers by the function: strcpy is vulnerable."""

    def __init__(self, final=None):
        self.chat_generator = FakeGenerator(final or [])

    def warm_up(self):
        pass

    def run(self, messages):
        question = messages[0].text
        if "f1(" in question and "strncpy" in question:
            raise RuntimeError("server went away")
        call = ToolCall(tool_name="search_security_kb", arguments={"query": "CWE-787"}, id="c1")
        answer = (
            "" if "f0(" in question and "strncpy" in question else (BENIGN if "strncpy" in question else VULNERABLE)
        )
        history = [
            messages[0],
            ChatMessage.from_assistant(tool_calls=[call]),
            ChatMessage.from_tool("No matching information was found", origin=call),
            ChatMessage.from_assistant(answer, meta={"usage": {"completion_tokens": 7}, "finish_reason": "stop"}),
        ]
        return {"messages": history, "last_message": history[-1], "step_count": 2}


def test_measure_scores_pairs_forces_lost_answers_and_resumes(tmp_path):
    tasks = load_tasks(write_benchmark(tmp_path / "b.jsonl"), "train")
    cache = tmp_path / "run" / "tasks.json"
    built = []

    def load(config):
        built.append(config)
        return FakeAgent(final=[ChatMessage.from_assistant(BENIGN)])

    metrics, records = measure(
        {"init_parameters": {"max_agent_steps": 2}},
        tasks,
        concurrency=1,
        cache=cache,
        load_agent=load,
        log=lambda _: None,
    )
    # train-0: the patched member's empty answer is forced into a benign verdict -> correct.
    # train-1: the patched member's run raised -> parse error.
    assert metrics.counts["correct"] == 1
    assert metrics.counts["parse_error"] == 1
    assert records["train-0-f"]["forced"] is True
    assert records["train-1-f"]["error"] == "RuntimeError: server went away"
    assert records["train-0-v"]["trajectory"][0] == {
        "tool": "search_security_kb",
        "args": '{"query":"CWE-787"}',
        "result": "No matching information was found",
        "failed": True,
    }
    assert records["train-0-v"]["generation"] == {"completion_tokens": [None, 7], "length_stops": 0}

    usage = tool_usage(records, {"init_parameters": {"max_agent_steps": 2}})
    assert usage["tool_calls"] == 3
    assert usage["failed_tool_calls"] == 3
    assert usage["tasks_at_step_cap"] == 3
    assert usage["forced_final_answers"] == 1
    assert usage["errors"] == 1

    # A second run reads every task from the cache and builds no agent.
    built.clear()
    again, _ = measure({}, tasks, cache=cache, load_agent=load, log=lambda _: None)
    assert built == []
    assert again.counts == metrics.counts


def test_compress_trajectory_pairs_calls_with_results():
    messages = [
        {"role": "user", "content": "the function"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": "1", "function": {"name": "kb", "arguments": "{}"}}],
        },
        {"role": "tool", "tool_call_id": "1", "content": "a briefing"},
        {"role": "assistant", "content": "final"},
    ]
    assert compress_trajectory(messages) == [{"tool": "kb", "args": "{}", "result": "a briefing"}, {"reply_chars": 5}]


def test_guard_gives_an_empty_reply_the_json_in_its_reasoning():
    empty = ChatMessage.from_assistant("", reasoning=ReasoningContent(reasoning_text=f"thinking... {BENIGN}"))
    blank = ChatMessage.from_assistant("")

    class Agent:
        chat_generator = FakeGenerator([empty, blank])

    agent = agents.guard_empty_replies(Agent())
    assert agent.chat_generator.run(messages=[])["replies"][0].text == BENIGN
    assert agent.chat_generator.run(messages=[])["replies"][0].text == agents.EMPTY_REPLY_TEXT
    assert agents.guard_empty_replies(agent) is agent


def test_force_final_answer_asks_again_for_the_json_alone():
    agent = FakeAgent(final=[ChatMessage.from_assistant(""), ChatMessage.from_assistant(VULNERABLE)])
    out = agents.force_final_answer(agent, {"messages": [ChatMessage.from_user("q")]})
    assert out["last_message"].text == VULNERABLE
    assert out["forced_final_answer"] is True
    assert agent.chat_generator.calls == 2


def test_force_final_answer_keeps_the_output_when_the_call_fails():
    class Failing:
        def run(self, messages, tools=None):
            raise RuntimeError("down")

    class Agent:
        chat_generator = Failing()

    out = {"messages": [], "last_message": None}
    assert agents.force_final_answer(Agent(), out) is out


def test_openai_messages():
    call = ToolCall(tool_name="search_security_kb", arguments={"query": "x"}, id="c1")
    converted = agents.openai_messages(
        [
            ChatMessage.from_user("q"),
            ChatMessage.from_assistant(tool_calls=[call]),
            ChatMessage.from_tool("r", origin=call, error=True),
            ChatMessage.from_assistant("done"),
        ]
    )
    assert converted == [
        {"role": "user", "content": "q"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "c1",
                    "type": "function",
                    "function": {"name": "search_security_kb", "arguments": '{"query":"x"}'},
                }
            ],
        },
        {"role": "tool", "tool_call_id": "c1", "content": "r", "name": "search_security_kb", "error": True},
        {"role": "assistant", "content": "done"},
    ]


def test_a_long_query_still_finds_its_sub_agent_trace():
    query = "which CWE class " + "is a write past the end of a heap buffer " * 10
    messages = [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": "1", "function": {"name": "search_security_kb", "arguments": json.dumps({"query": query})}}
            ],
        },
        {"role": "tool", "tool_call_id": "1", "content": "a briefing"},
    ]
    traces = {query.strip(): {"query": query, "usage": {"calls": 3}, "steps": 3, "documents": 2, "seconds": 1.0}}
    steps = attach_sub_agent_traces(compress_trajectory(messages), traces.pop, messages)
    assert len(steps[0]["args"]) == 200
    assert steps[0]["sub_agent"]["usage"] == {"calls": 3}
