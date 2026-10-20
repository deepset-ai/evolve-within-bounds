# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gui"))
import server as gui  # noqa: E402

FAKE_DEMO = """
import sys
print("\\x1b[1m=== 6. a person approves ===\\x1b[0m")
answer = input("    Deploy c001? Type 'yes' to approve: ")
print("deployed" if answer.strip() == "yes" else "not deployed")
"""


def _wait(condition, timeout=20.0):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.05)


def test_the_demo_runs_in_a_terminal_and_takes_the_answer_from_the_page():
    run = gui.DemoRun([sys.executable, "-c", FAKE_DEMO])
    _wait(lambda: run.awaiting)
    run.answer(approve=True)
    _wait(lambda: run.done)
    output = "".join(run.chunks)
    assert run.returncode == 0 and "\x1b[1m=== 6." in output  # colours survive: the demo sees a terminal
    assert "yes" in output.split("approve:")[1] and output.rstrip().endswith("deployed")
    assert not run.awaiting


@pytest.fixture
def results(tmp_path, monkeypatch):
    """A checkout with one integration, and somewhere to keep its scans."""
    monkeypatch.setattr(gui, "RESULTS", tmp_path / "results")
    monkeypatch.setattr(gui, "CHECKOUT", tmp_path / "checkout")
    code = tmp_path / "checkout" / "integrations" / "store" / "src"
    code.mkdir(parents=True)
    (code / "store.py").write_text("".join(f"line {n}\n" for n in range(1, 31)))
    return gui.RESULTS


def _write(results, findings, complete=True):
    results.mkdir(exist_ok=True)
    gui.result_path("store").write_text(json.dumps({"findings": findings, "complete": complete, "record": {"x": 1}}))


def _finding(start, end=None):
    return {"path": "src/store.py", "line_start": start, "line_end": end or start, "cwe": "CWE-89", "title": "SQL"}


def test_only_the_approved_result_is_shown_and_a_rescan_needs_a_new_approval(results):
    config = {"repository": "https://example.org/repo.git", "commit": "a" * 40, "integrations": [{"name": "store"}]}
    shown = gui.Gui()
    shown.config = config

    _write(results, [_finding(12)])
    assert shown.integrations() == []
    assert gui.set_approval(["store"], by="reviewer") == []
    [view] = shown.integrations()
    assert "record" not in view and view["url"] == f"https://example.org/repo/tree/{'a' * 40}/integrations/store"
    [finding] = view["findings"]
    assert [line["n"] for line in finding["excerpt"] if line["hit"]] == [12] and finding["excerpt"][0]["n"] == 9
    assert finding["cwe_name"].startswith("SQL injection")

    _write(results, [_finding(12), _finding(20)])  # scanned again: not what was reviewed
    assert shown.integrations() == []
    _write(results, [], complete=False)
    assert gui.set_approval(["store"], by="reviewer") == ["store"]  # an unfinished scan is no verdict
    gui.set_approval(["store"], by="reviewer", approve=False)
    assert gui._approvals() == {}


def test_the_files_read_come_from_the_scan_record(results):
    root = gui.CHECKOUT / "integrations" / "store"
    reads = [{"path": "src/store.py", "start": 1, "end": 9}, {"path": "src/store.py"}, {"path": "../../outside.py"}]
    assert gui._files_read({"record": {"agent": {"reads": reads}}}, root) == [
        {"path": "../../outside.py", "lines": None},  # never read from outside the integration
        {"path": "src/store.py", "lines": 30},
    ]
    assert gui._files_read({}, root) == []


def test_a_sentence_the_agent_cut_short_is_shown_once_and_ends_on_a_word(results):
    why = (
        "_guard is the project's guard for this kind of value "
        + "and is applied at other statements of the same kind (store.py:3, store.py:9)"
    )
    view = gui.finding_view({**_finding(12), "title": why[:110], "missing_control": why}, gui.CHECKOUT)
    assert view["title"] == why and view["why"] == ""
    whole = why.removesuffix(" (store.py:3, store.py:9)") + "; here the value is passed on without it"
    view = gui.finding_view({**_finding(12), "title": whole[:110], "missing_control": whole}, gui.CHECKOUT)
    assert view["title"] == whole  # the whole sentence, though it is long and ends in a letter
    cut = ("words " * 40)[:200]  # as the agent cuts it: at 200 characters, in a word
    view = gui.finding_view({**_finding(12), "title": "SQL", "missing_control": cut}, gui.CHECKOUT)
    assert view["title"] == "SQL" and view["why"].endswith("words …") and len(view["why"]) < 200
    assert gui.finding_view(_finding(12), gui.CHECKOUT)["title"] == "SQL"  # a short title stays as it is


def test_a_pair_shows_both_functions_the_diff_and_the_agents_two_verdicts(tmp_path, monkeypatch):
    # Two made-up C functions: the patched one adds a NULL check.
    before = "int f(char *p)\n{\n    return p[0];\n}\n"
    after = "int f(char *p)\n{\n    if (p == NULL)\n        return 0;\n    return p[0];\n}\n"
    data = tmp_path / "bench.jsonl"
    rows = [
        {
            "id": "11",
            "code": before,
            "lang": "c",
            "gold_is_vulnerable": True,
            "gold_cwe": "CWE-476",
            "pair_id": "p1",
            "split": "holdout",
        },
        {
            "id": "12",
            "code": after,
            "lang": "c",
            "gold_is_vulnerable": False,
            "gold_cwe": "CWE-476",
            "pair_id": "p1",
            "split": "holdout",
        },
        {
            "id": "13",
            "code": before,
            "lang": "c",
            "gold_is_vulnerable": True,
            "gold_cwe": "CWE-125",
            "pair_id": "p2",
            "split": "holdout",
        },
        {
            "id": "14",
            "code": after,
            "lang": "c",
            "gold_is_vulnerable": False,
            "gold_cwe": "CWE-125",
            "pair_id": "p2",
            "split": "holdout",
        },
        {
            "id": "15",
            "code": before,
            "lang": "c",
            "gold_is_vulnerable": True,
            "gold_cwe": "CWE-787",
            "pair_id": "p3",
            "split": "holdout",
        },
    ]
    data.write_text("".join(json.dumps(r) + "\n" for r in rows))
    meta = tmp_path / "meta.json"
    meta.write_text(
        json.dumps(
            {
                "11": {
                    "project": "demo",
                    "project_url": "https://example.org/demo",
                    "commit_id": "abc",
                    "file_name": "None",
                }
            }
        )
    )
    monkeypatch.setattr(gui, "PAIRS", tmp_path / "work" / "pairs.jsonl")
    monkeypatch.setattr(gui, "PAIR_RUNS", tmp_path / "runs")
    config = {"data": str(data), "meta": str(meta), "agent": "agents/primevul/looped", "pairs": ["p1", "p2", "p3"]}

    assert gui.pairs_view(config) == []  # nothing copied or judged yet
    assert len(gui._rows(gui.pairs_file(config))) == 5
    run_dir = gui.pair_run_dir(config)
    run_dir.mkdir(parents=True)
    verdict = lambda vulnerable, lines=(): {
        "is_vulnerable": vulnerable,
        "cwe": "CWE-476",
        "vulnerable_lines": list(lines),
        "rationale": "  p may be NULL.  ",
        "parse_error": False,
    }  # noqa: E731
    records = [
        {
            "task_id": "11",
            "pair_id": "p1",
            "verdict": verdict(True, [3]),
            "seconds": 61.4,
            "trajectory": [{"tool": "search_security_kb"}],
        },
        {"task_id": "12", "pair_id": "p1", "verdict": verdict(False), "seconds": 40.0, "trajectory": []},
        {
            "task_id": "13",
            "pair_id": "p2",
            "verdict": verdict(True, [9]),
            "seconds": 50.0,
            "trajectory": [],
        },  # its twin is not judged yet
    ]
    (run_dir / "tasks.json").write_text(json.dumps(records))

    [view] = gui.pairs_view(config)  # p2 waits for its twin; p3 has no twin at all
    assert (
        view["id"] == "p1" and view["project"] == "demo" and view["commit_url"] == "https://example.org/demo/commit/abc"
    )
    assert view["file"] == ""  # PrimeVul's "None" is no file name
    assert view["cwe_name"].startswith("Null pointer dereference") and view["first"] in ("vulnerable", "patched")
    changed = lambda side: [line["n"] for line in view[side]["lines"] if line["changed"]]  # noqa: E731
    assert changed("vulnerable") == [] and changed("patched") == [3, 4]  # the fix only adds the NULL check
    assert (
        view["vulnerable"]["verdict"] == "vulnerable"
        and view["vulnerable"]["right"]
        and view["vulnerable"]["flagged"] == [3]
    )
    assert (
        view["vulnerable"]["rationale"] == "p may be NULL."
        and view["vulnerable"]["lookups"] == 1
        and view["vulnerable"]["seconds"] == 61
    )
    assert view["patched"]["verdict"] == "benign" and view["patched"]["right"] and view["right"]


def test_the_verdicts_can_come_from_an_earlier_run(tmp_path, monkeypatch):
    data = tmp_path / "bench.jsonl"
    rows = [
        {
            "id": "21",
            "code": "int a;\n",
            "lang": "c",
            "gold_is_vulnerable": True,
            "gold_cwe": "CWE-476",
            "pair_id": "q1",
            "split": "holdout",
        },
        {
            "id": "22",
            "code": "int a = 0;\n",
            "lang": "c",
            "gold_is_vulnerable": False,
            "gold_cwe": "CWE-476",
            "pair_id": "q1",
            "split": "holdout",
        },
        {
            "id": "23",
            "code": "int b;\n",
            "lang": "c",
            "gold_is_vulnerable": True,
            "gold_cwe": "CWE-125",
            "pair_id": "q2",
            "split": "holdout",
        },
        {
            "id": "24",
            "code": "int b = 0;\n",
            "lang": "c",
            "gold_is_vulnerable": False,
            "gold_cwe": "CWE-125",
            "pair_id": "q2",
            "split": "holdout",
        },
    ]
    data.write_text("".join(json.dumps(r) + "\n" for r in rows))
    monkeypatch.setattr(gui, "PAIRS", tmp_path / "work" / "pairs.jsonl")
    monkeypatch.setattr(gui, "PAIR_RUNS", tmp_path / "runs")
    config = {
        "data": str(data),
        "meta": str(tmp_path / "none.json"),
        "agent": "agents/primevul/looped",
        "pairs": ["q1", "q2"],
    }
    said = lambda vulnerable: {
        "is_vulnerable": vulnerable,
        "cwe": None,
        "vulnerable_lines": [],
        "rationale": "r",
        "parse_error": False,
    }  # noqa: E731
    earlier = tmp_path / "earlier.json"
    earlier.write_text(
        json.dumps(
            [
                {"task_id": "21", "pair_id": "q1", "verdict": said(True)},
                {"task_id": "22", "pair_id": "q1", "verdict": said(False)},
                {"task_id": "23", "pair_id": "q2", "verdict": said(True)},  # its twin was not judged in that run
                {"task_id": "99", "pair_id": "qx", "verdict": said(True)},  # not a chosen pair
            ]
        )
    )
    assert gui.import_pairs(config, earlier) == 0
    kept = json.loads((gui.pair_run_dir(config) / "tasks.json").read_text())
    assert [r["task_id"] for r in kept] == ["21", "22", "23"]
    assert [(p["id"], p["right"]) for p in gui.pairs_view(config)] == [("q1", True)]  # q2 waits for its twin


def test_the_integrations_are_pinned():
    config = gui.load_integrations()
    names = [entry["name"] for entry in config["integrations"]]
    assert len(set(names)) == len(names) and all(
        entry.get("about") and entry.get("group") for entry in config["integrations"]
    )
    assert len(config["commit"]) == 40 and int(config["commit"], 16) >= 0


def test_the_evolution_data_is_consistent():
    data = json.loads((gui.HERE / "evolution.json").read_text())
    versions = data["versions"]
    ids = [v["id"] for v in versions]
    assert versions[0]["parent"] is None and all(v["parent"] in ids[:i] for i, v in enumerate(versions) if i)
    assert all(0 <= v["train"] <= data["train_pairs"] for v in versions)
    assert all(v["val"] is None or 0 <= v["val"] <= data["val_pairs"] for v in versions)
    presented = next(v for v in versions if v["id"] == data["presented"]["id"])
    assert presented["val"] == max(v["val"] for v in versions if v["val"] is not None)  # picked on validation
    staged = [i for stage in data.get("stages", []) for i in stage["versions"]]
    assert len(staged) == len(set(staged)) and set(staged) <= set(ids[1:])


@pytest.fixture
def served(results, monkeypatch):
    monkeypatch.setattr(gui, "PAIRS", results / "no-pairs.jsonl")
    gui.Handler.gui = gui.Gui()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), gui.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_the_page_its_files_and_nothing_else_are_served(served):
    def get(path):
        try:
            with urllib.request.urlopen(served + path) as response:  # noqa: S310 - the test's own server
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, b""

    status, page = get("/")
    assert status == 200 and page.startswith(b"<!doctype html>")
    assert get("/static/gui.js")[0] == 200
    assert json.loads(get("/api/evolution")[1])["presented"]["id"] == "v5"
    assert get("/recording/timing.log")[0] == 200
    assert get("/api/integrations") == (200, b"[]")  # nothing approved
    assert get("/api/pairs") == (200, b"[]")  # nothing judged
    assert get("/static/../server.py")[0] == 404
    assert get("/static/%2e%2e/server.py")[0] == 404
