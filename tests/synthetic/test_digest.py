# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json

import pytest
from helpers import PAIR, OnePairBench, pair_files

from security_agent.synthetic.bench.pairs import pair_targets
from security_agent.synthetic.digest import pair_digest, render, shown_material
from security_agent.synthetic.traces import ReasoningReader, shorten


def _full(items):
    return [{"path": "src/fetch.py", "line_end": i["line_start"], "title": "t", "confidence": 80, **i} for i in items]


@pytest.mark.parametrize(
    "row, reported, by_agent, labels",
    [
        ({"mutant_localized": False}, [], [], ["missed"]),
        ({"mutant_localized": False}, [{"line_start": 12, "cwe": "CWE-918"}], [], ["wrong_lines_near"]),
        ({"mutant_localized": False}, [{"line_start": 30, "cwe": "CWE-918"}], [], ["wrong_lines_far"]),
        ({"mutant_localized": False}, [], [{"line_start": 5, "cwe": "CWE-918"}], ["missed", "reported_then_dropped"]),
        (
            {"mutant_localized": True, "baseline_mapped_localization_alarm": True},
            [{"line_start": 5, "cwe": "CWE-918"}],
            [],
            ["safe_twin_flagged"],
        ),
    ],
)
def test_pair_digest_labels(tmp_path, row, reported, by_agent, labels):
    digest = pair_digest(
        "hvbench",
        {"pair_id": "pair-x", **row},
        PAIR,
        pair_files(tmp_path),
        {
            "mutant": _full(reported),
            "baseline": _full(reported) if row.get("baseline_mapped_localization_alarm") else [],
        },
        {"mutant": {"candidates": _full(by_agent)}, "baseline": {}},
    )
    assert digest["labels"] == labels
    text = render(digest)
    assert ">     5 |     return requests.get(url)" in text and ">     5 |     return requests.get(check(url))" in text
    assert "    return requests.get(url)" in shown_material([digest])["code"]


AGENT = {
    "stop": "max_steps",
    "steps": 15,
    "reads": [{"path": "src/fetch.py", "start": 1, "end": 3}],
    "tool_calls": [{"tool": "read_file", "ok": True}, {"tool": "search", "ok": False, "error": "error: boom"}],
    "reported": [
        {
            "path": "src/fetch.py",
            "line_start": 9,
            "line_end": 9,
            "cwe": "CWE-918",
            "confidence": 60,
            "title": "fetch",
            "missing_control": "no allow-list",
        }
    ],
    "trajectory": [
        {"role": "user", "text": "Files: src/fetch.py"},
        {
            "role": "assistant",
            "reasoning": "I should look at fetch.py, `requests.get(url) is suspicious`",
            "calls": [{"tool": "read_file", "args": "{}"}],
        },
        {
            "role": "tool",
            "results": [
                {
                    "tool": "read_file",
                    "error": False,
                    "result": "src/fetch.py (30 lines), lines 1-3:\n    1 | import requests as http_client_library",
                }
            ],
        },
    ],
}
MUTANT = {"agent": AGENT, "candidates": AGENT["reported"], "components": []}
BASELINE = {"agent": {**AGENT, "stop": "answered", "steps": 4, "reads": []}, "candidates": [], "components": []}


def test_digest_shows_what_the_agent_did(tmp_path):
    digest = pair_digest(
        "hvbench",
        {"pair_id": "pair-x", "mutant_localized": False},
        PAIR,
        pair_files(tmp_path),
        {"mutant": [], "baseline": []},
        {"mutant": MUTANT, "baseline": BASELINE},
    )
    text = render(digest)
    assert "- The agent (vulnerable repo): stopped (max_steps) after 15 steps; 1 findings reported" in text
    assert "- The agent read this file (vulnerable repo): lines 1-3; the planted lines were NOT read" in text
    assert (
        "Reported by the agent (before your later steps) within 10 lines" in text
        and "(explanation: no allow-list)" in text
    )


def test_reasoning_reader_shows_the_agent_conversation(tmp_path):
    shown = []
    bench = OnePairBench(tmp_path)
    reader = ReasoningReader(
        {"hvbench": ["pair-x"]},
        lambda b, iid: MUTANT if iid == "m1" else None,
        on_shown=shown.append,
        bench_loader=lambda name: bench,
    )
    out = json.loads(reader("hvbench/pair-x"))
    assert out["stop"] == "max_steps" and out["reported_in_planted_files"][0]["line_start"] == 9
    assert [s["role"] for s in out["conversation"]] == ["user", "assistant", "tool"] and out["tool_errors"][0][
        "tool"
    ] == "search"
    assert "import requests as http_client_library" in shown[0]["code"]  # quoted code becomes leakage material
    assert "requests.get(url) is suspicious" in shown[0]["code"]
    assert "not a training pair" in json.loads(reader("hvbench/pair-y"))["error"]
    assert "no saved record" in json.loads(reader("hvbench/pair-x", "safe_twin"))["error"]


def test_shorten_keeps_head_tail_and_mentions():
    text = "a" * 5000 + " line 42 here " + "b" * 5000
    out = shorten(text, 3000, ["42"])
    assert len(out) < 3600 and out.startswith("aaa") and out.endswith("bbb") and "line 42 here" in out
    assert shorten("short", 100, ["x"]) == "short"


def test_pair_targets_prefers_the_sink():
    spans = {"mutant_line_start": 5, "mutant_line_end": 5, "baseline_line_start": 5, "baseline_line_end": 5}
    sink, source = {"path": "a.py", "role": "sink", **spans}, {"path": "b.py", "role": "source", **spans}
    assert pair_targets({"targets": [source, sink]}) == [sink]
    assert pair_targets({"targets": [source]}) == [source]  # no sink: every target
    assert pair_targets({"pair_id": "x"}) == []
