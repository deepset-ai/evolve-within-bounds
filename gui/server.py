# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The GUI: how the agent evolved, the live demo, and the agent's verdict on real Haystack integrations.

  hatch run synthetic:gui                    http://127.0.0.1:8765
  hatch run synthetic:gui --host 0.0.0.0     reachable from another machine on the network
  hatch run synthetic:gui --prepare          before showing the page: scan the integrations in integrations.yaml
  hatch run synthetic:gui --review           print every scan's findings, for the person who reviews them
  hatch run synthetic:gui --approve NAME ... put reviewed integrations on the page (--revoke takes them off)
  hatch run synthetic:gui --prepare-pairs    judge the PrimeVul pairs in pairs.yaml with the PrimeVul agent
  hatch run synthetic:gui --import-pairs F   take their verdicts from an earlier run's tasks.json instead
  hatch run synthetic:gui --snapshot NAME ...  write what the page shows of these approved integrations, and of the
                                             judged pairs, to shipped/ for the repository

The page (static/) has three parts:
- **How the agent evolved:** evolution.json, the loop run behind results/synthetic.md, as aggregates.
- **Watch it improve:** demo/run_demo.sh in a pseudo-terminal, streamed to the page as it prints (server-sent events);
  the page's Approve button answers the demo's prompt. Without a model server or sandbox, the page plays the recorded
  run in demo/recording instead.
- **Scan a Haystack integration:** integrations from deepset-ai/haystack-core-integrations at a pinned commit, scanned
  by the evolved agent inside the sandbox. Real code can hold real, unreported vulnerabilities, so nothing is scanned
  live: every result is reviewed by a person first, and the page shows only approved ones. An approval holds for that
  exact result. Results and approvals stay on this machine, in runs/gui/integrations/. Without any here, the page
  shows the integrations in shipped/integrations.json, which we reviewed and approved.
- **Spot the vulnerability:** pairs of real C functions from PrimeVul (pairs.yaml), a function before a public security
  fix and the patched version, side by side with the lines that differ marked. The visitor guesses which one is
  vulnerable; the page then shows the PrimeVul agent's verdict on each, from a run of the agent on those pairs
  (--prepare-pairs). The functions and the verdicts stay on this machine, in work/gui/ and runs/gui/pairs/. Without
  them, the page shows the pairs in shipped/pairs.json.

Only the standard library and this repository's package.
"""

from __future__ import annotations

import argparse
import codecs
import collections
import contextlib
import difflib
import fcntl
import hashlib
import json
import os
import pty
import signal
import struct
import subprocess
import sys
import termios
import textwrap
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
STATIC = HERE / "static"
RECORDING = REPO / "demo" / "recording"
CHECKOUT = REPO / "work" / "gui" / "haystack-core-integrations"
RESULTS = REPO / "runs" / "gui" / "integrations"
AGENT = REPO / "agents" / "synthetic" / "looped"  # the evolved agent
PAIRS = REPO / "work" / "gui" / "primevul-pairs.jsonl"  # the chosen pairs' functions, copied from the benchmark file
PAIR_RUNS = REPO / "runs" / "gui" / "pairs"  # the PrimeVul agent's verdicts on them
# What the page showed on our machine, for a fresh checkout: the integrations we approved, and the judged pairs.
SHIPPED = HERE / "shipped"
SANDBOX = os.environ.get("SANDBOX", "security-agent")
MODEL_URL = "http://127.0.0.1:8000/v1"
PROMPT = "Type 'yes' to approve: "
COLUMNS = 110
CONTEXT = 3  # lines shown around a finding
MAX_EXCERPT = 14
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".webp": "image/webp",
    ".woff2": "font/woff2",
    ".txt": "text/plain; charset=utf-8",
    ".log": "application/octet-stream",
    ".diff": "text/plain; charset=utf-8",
}
# Plain-language names for weaknesses a visitor is likely to see; others fall back to MITRE's name.
PLAIN_CWE = {
    "CWE-20": "Missing input validation",
    "CWE-22": "Path traversal: input decides which file is opened",
    "CWE-78": "Command injection: input becomes part of a shell command",
    "CWE-79": "Cross-site scripting: input lands in a web page unescaped",
    "CWE-89": "SQL injection: input becomes part of a database query",
    "CWE-94": "Code injection: input is run as code",
    "CWE-117": "Log injection: input is written to the logs unchecked",
    "CWE-119": "Buffer overflow: a read or write runs past the end of a buffer",
    "CWE-125": "Out-of-bounds read: data is read from past the end of a buffer",
    "CWE-190": "Integer overflow: a number grows past what its type can hold",
    "CWE-362": "Race condition: two things happen at once and step on each other",
    "CWE-401": "Memory leak: memory is taken and never given back",
    "CWE-415": "Double free: the same memory is freed twice",
    "CWE-416": "Use after free: memory is used after it was given back",
    "CWE-476": "Null pointer dereference: a missing pointer is used as if it were there",
    "CWE-787": "Out-of-bounds write: data is written past the end of a buffer",
    "CWE-835": "Infinite loop: a loop that may never end",
    "CWE-200": "Information exposure: data reaches someone who shouldn't see it",
    "CWE-522": "Exposed credential: a secret ends up where others can read it",
    "CWE-532": "A secret is written to a log",
    "CWE-798": "Hard-coded secret: a password or token is written into the code",
    "CWE-918": "Server-side request forgery: input decides which address is fetched",
}


def cwe_name(cwe: str) -> str:
    """A weakness in plain words, or MITRE's name for it."""
    if cwe in PLAIN_CWE:
        return PLAIN_CWE[cwe]
    reference = REPO / "src" / "security_agent" / "knowledge_base" / "cwe_reference.json"
    try:
        return json.loads(reference.read_text(encoding="utf-8")).get(cwe, {}).get("name", cwe)
    except (OSError, ValueError):
        return cwe


# -- the live demo ------------------------------------------------------------------------------------------------


class DemoRun:
    """One run of demo/run_demo.sh in a pseudo-terminal; its output is kept for every viewer of the page."""

    def __init__(self, command: list[str]) -> None:
        self.chunks: list[str] = []
        self.awaiting = False
        self.returncode: int | None = None
        self.started = time.time()
        self.cond = threading.Condition()
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, COLUMNS, 0, 0))
        env = {**os.environ, "COLUMNS": str(COLUMNS), "LINES": "50", "TERM": "xterm-256color"}
        self.process = subprocess.Popen(  # noqa: S603 - our own script
            command, stdin=slave, stdout=slave, stderr=slave, cwd=REPO, env=env, start_new_session=True
        )
        os.close(slave)
        self.master = master
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        tail = ""
        while True:
            try:
                data = os.read(self.master, 4096)
            except OSError:  # the terminal closes when the run ends
                data = b""
            if not data:
                break
            text = decoder.decode(data)
            with self.cond:
                self.chunks.append(text)
                tail = (tail + text)[-300:]
                if PROMPT in tail and "\n" not in tail.rsplit(PROMPT, 1)[1]:
                    self.awaiting = True
                self.cond.notify_all()
        code = self.process.wait()
        os.close(self.master)
        with self.cond:
            self.returncode, self.awaiting = code, False
            self.cond.notify_all()

    @property
    def done(self) -> bool:
        """Has the run ended?"""
        return self.returncode is not None

    def answer(self, approve: bool) -> None:
        """Answer the demo's approval prompt."""
        with self.cond:
            if not self.awaiting:
                return
            self.awaiting = False
            self.cond.notify_all()
        os.write(self.master, b"yes\n" if approve else b"no\n")

    def stop(self) -> None:
        """End the run and everything it started."""
        if not self.done:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.process.pid, signal.SIGTERM)


# -- the integrations ---------------------------------------------------------------------------------------------


def load_integrations() -> dict[str, Any]:
    """integrations.yaml: the repository, its pinned commit, and the integrations the page offers."""
    return yaml.safe_load((HERE / "integrations.yaml").read_text(encoding="utf-8"))


def checkout(config: dict[str, Any]) -> Path:
    """haystack-core-integrations at the pinned commit, in work/gui/ (cloned once)."""
    git = ["git", "-C", str(CHECKOUT)]
    if not (CHECKOUT / ".git").is_dir():
        CHECKOUT.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--quiet", "--filter=blob:none", config["repository"], str(CHECKOUT)], check=True
        )  # noqa: S607
    head = subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if head != config["commit"]:
        subprocess.run([*git, "fetch", "--quiet", "origin", config["commit"]], check=True)
        subprocess.run([*git, "-c", "advice.detachedHead=false", "checkout", "--quiet", config["commit"]], check=True)
    return CHECKOUT


def result_path(name: str) -> Path:
    """Where an integration's latest scan is kept."""
    return RESULTS / f"{name}.json"


def _result(name: str) -> dict[str, Any] | None:
    path = result_path(name)
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def _approvals() -> dict[str, Any]:
    path = RESULTS / "approved.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def approved(name: str) -> bool:
    """Was this integration's current result reviewed and approved? A new scan needs a new approval."""
    entry, path = _approvals().get(name), result_path(name)
    return bool(entry and path.is_file() and entry.get("sha256") == _sha256(path))


def set_approval(names: list[str], by: str, approve: bool = True) -> list[str]:
    """Approve (or revoke) integrations' current results; returns the names without a finished scan to approve."""
    entries, missing = _approvals(), []
    for name in names:
        result = _result(name)
        if not approve:
            entries.pop(name, None)
        elif result and result.get("complete", True):
            entries[name] = {"sha256": _sha256(result_path(name)), "by": by, "at": time.strftime("%Y-%m-%d %H:%M")}
        else:
            missing.append(name)
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "approved.json").write_text(json.dumps(entries, indent=1), encoding="utf-8")
    return missing


def scan(name: str, root: Path) -> int:
    """Scan one integration with the evolved agent, inside the sandbox; a finished scan replaces the earlier one."""
    RESULTS.mkdir(parents=True, exist_ok=True)
    fresh = result_path(name).with_suffix(".new")
    fresh.unlink(missing_ok=True)
    env = {**os.environ, "HAYSTACK_TELEMETRY_ENABLED": "False", "PYTHONWARNINGS": "ignore"}
    command = [
        sys.executable, "-m", "security_agent.cli", "synthetic", "scan", str(root / "integrations" / name),
        "--candidate", str(AGENT), "--sandbox", SANDBOX, "--out", str(fresh),
    ]  # fmt: skip
    with result_path(name).with_suffix(".log").open("w", encoding="utf-8") as log:
        code = subprocess.run(command, cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT, check=False).returncode  # noqa: S603
    if fresh.is_file():
        fresh.replace(result_path(name))
    return code


def _excerpt(path: Path, start: int, end: int) -> list[dict[str, Any]]:
    """Numbered lines around `start`..`end` of a file, the lines themselves marked."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    end = min(end, start + MAX_EXCERPT - 1)
    first, last = max(1, start - CONTEXT), min(len(lines), end + CONTEXT)
    return [{"n": n, "text": lines[n - 1], "hit": start <= n <= end} for n in range(first, last + 1)]


def _whole_words(text: str, limit: int) -> str:
    """`text`, ended at its last whole word and marked " …" if it was cut at its character limit (`limit`)."""
    if len(text) < limit or " " not in text or not (text[-1].isalnum() or text[-1] in "_ "):
        return text  # shorter than the limit, or ending on a sentence's last mark: whole
    if text[-1] != " ":
        text = text[: text.rfind(" ")]
    return text.rstrip(" ,;:(") + " …"


def _finding_key(path: Any, line_start: Any, title: Any) -> tuple[str, str, str]:
    return str(path), str(line_start), str(title)[:200]


EXPLANATION_CHARS = 300  # what the scanner keeps of the agent's explanation with each finding


def _call_args(text: str) -> tuple[dict[str, Any], bool]:
    """
    A recorded tool call's arguments, and whether they are whole.

    The record keeps the first 800 characters of the arguments' JSON. The explanation comes last, so a cut call still
    holds the rest and the start of the explanation: the JSON is closed after the last character that keeps it valid.
    """
    try:
        args = json.loads(text)
        return (args, True) if isinstance(args, dict) else ({}, False)
    except ValueError:
        pass
    for end in range(len(text), max(0, len(text) - 8), -1):  # past a cut escape such as `\u00`
        try:
            args = json.loads(text[:end] + '"}')
        except ValueError:
            continue
        return (args, False) if isinstance(args, dict) else ({}, False)
    return {}, False


def explanations(result: dict[str, Any]) -> dict[tuple[str, str, str], tuple[str, bool]]:
    """
    The agent's own explanation of each finding, and whether it is whole, from its calls in the scan's record.

    The scanner keeps only the explanation's first 300 characters with the finding; its `report_finding` call holds
    more of it.
    """
    found = {}
    for step in ((result.get("record") or {}).get("agent") or {}).get("trajectory") or []:
        for call in step.get("calls") or []:
            if call.get("tool") != "report_finding":
                continue
            args, whole = _call_args(call.get("args") or "")
            if args.get("explanation"):
                key = _finding_key(args.get("path"), args.get("line_start"), args.get("title"))
                found[key] = (str(args["explanation"]), whole)
    return found


def full_explanation(finding: dict[str, Any], known: dict[tuple[str, str, str], tuple[str, bool]]) -> tuple[str, bool]:
    """
    The finding's explanation, and whether it is whole.

    That is the agent's own from its call, if the stored one is the start of it: all of it, or at least more of it
    than the scanner kept. Otherwise it is the stored one, whole if shorter than what the scanner keeps.
    """
    why = str(finding.get("missing_control") or finding.get("evidence") or "")
    longer, whole = known.get(
        _finding_key(finding.get("path"), finding.get("line_start"), finding.get("title")), ("", False)
    )
    if why and longer.startswith(why) and len(longer) > len(why):
        return longer, whole
    return why, len(why) < EXPLANATION_CHARS


def finding_view(
    finding: dict[str, Any], root: Path, known: dict[tuple[str, str, str], tuple[str, bool]] | None = None
) -> dict[str, Any]:
    """One finding as the page shows it: where, what it noticed, why it matters, the call to check, and the code."""
    start, end = int(finding["line_start"]), int(finding["line_end"])
    title = _whole_words(str(finding["title"]), 200)  # the scanner keeps 200 characters of the title
    why, whole = full_explanation(finding, known or {})
    if not whole:
        why = _whole_words(why, min(len(why), EXPLANATION_CHARS))
    if len(why) > len(title) and why.startswith(title.removesuffix(" …")):
        title, why = why, ""  # the title is the start of the agent's own sentence: show the sentence once
    return {
        "file": finding["path"],
        "lines": [start, end],
        "cwe": finding["cwe"],
        "cwe_name": cwe_name(finding["cwe"]),
        "title": title,
        "severity": finding.get("severity"),
        "why": why,
        "fix": _whole_words(str(finding.get("fix") or ""), 200),
        "sink": _whole_words(str(finding.get("sink") or ""), 120),
        "excerpt": _excerpt(root / finding["path"], start, end),
    }


def _files_read(result: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    """The files the agent opened during the scan, with their length, from the scan's own record."""
    reads = ((result.get("record") or {}).get("agent") or {}).get("reads") or []
    files = []
    for path in sorted({str(r["path"]) for r in reads if r.get("path")}):
        file, lines = (root / path).resolve(), None
        if root.resolve() in file.parents and file.is_file():
            with file.open("rb") as handle:
                lines = sum(1 for _ in handle)
        files.append({"path": path, "lines": lines})
    return files


def integration_view(entry: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """An approved integration for the page: what it is, and the evolved agent's verdict on it."""
    name = entry["name"]
    path = result_path(name)
    result = _result(name) or {}
    coverage = result.get("coverage") or {}
    cost = result.get("cost") or {}
    root = CHECKOUT / "integrations" / name
    known = explanations(result)
    return {
        "name": name,
        "title": entry.get("title", name),
        "about": entry.get("about", ""),
        "group": entry.get("group", ""),
        "findings": [finding_view(f, root, known) for f in result.get("findings", [])],
        "read": _files_read(result, root),
        "seconds": round(float(cost.get("seconds") or 0)),
        "calls": int(cost.get("calls") or 0),
        "tokens": int(cost.get("prompt_tokens") or 0) + int(cost.get("completion_tokens") or 0),
        "files": coverage.get("files"),
        "reviewed": coverage.get("reviewed"),
        "commit": config["commit"][:7],
        "url": f"{config['repository'].removesuffix('.git')}/tree/{config['commit']}/integrations/{name}",
        "scanned_at": time.strftime("%Y-%m-%d", time.localtime(path.stat().st_mtime)),
    }


# -- the PrimeVul pairs ---------------------------------------------------------------------------------------------


def load_pairs_config() -> dict[str, Any]:
    """pairs.yaml: the benchmark file, its metadata, the agent, and the pairs the page offers."""
    return yaml.safe_load((HERE / "pairs.yaml").read_text(encoding="utf-8"))


def _rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def pairs_file(config: dict[str, Any]) -> Path:
    """The chosen pairs' records, copied from the benchmark file into work/gui/, where the agent's run reads them."""
    wanted = set(config["pairs"])
    chosen = [r for r in _rows(REPO / config["data"]) if r.get("pair_id") in wanted]
    PAIRS.parent.mkdir(parents=True, exist_ok=True)
    PAIRS.write_text("".join(json.dumps(r) + "\n" for r in chosen), encoding="utf-8")
    return PAIRS


def pair_run_dir(config: dict[str, Any]) -> Path:
    """Where the agent's run on the chosen pairs lives (its tasks.json holds one record per function)."""
    return PAIR_RUNS / Path(config["agent"]).name


def prepare_pairs(config: dict[str, Any]) -> int:
    """Judge the chosen pairs' functions with the PrimeVul agent, through its own command; an earlier run resumes."""
    data = pairs_file(config)
    run_dir = pair_run_dir(config)
    env = {**os.environ, "HAYSTACK_TELEMETRY_ENABLED": "False"}
    env.setdefault("OPENAI_API_KEY", "none")  # the local model server takes any key
    command = [
        "hatch", "run", "primevul:run", "--agent", config["agent"], "--split", "test", "--data", str(data),
        "--run-dir", str(run_dir), "--concurrency", "4",
    ]  # fmt: skip
    print(f"judging {len(config['pairs'])} pairs with {config['agent']} -> {run_dir}", flush=True)
    code = subprocess.run(command, cwd=REPO, env=env, check=False).returncode  # noqa: S603
    shown = len(pairs_view(config))
    print(f"{shown} of {len(config['pairs'])} pairs judged in full and on the page")
    return code


def import_pairs(config: dict[str, Any], source: Path) -> int:
    """
    Take the chosen pairs' verdicts from an earlier run's tasks.json instead of judging the pairs again.

    For example the run behind results/primevul.md. A pair that run did not judge stays off the page until
    --prepare-pairs judges it.
    """
    wanted = {str(r["id"]) for r in _rows(pairs_file(config))}
    records = [r for r in json.loads(source.read_text(encoding="utf-8")) if str(r.get("task_id")) in wanted]
    run_dir = pair_run_dir(config)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "tasks.json").write_text(json.dumps(records), encoding="utf-8")
    shown = {p["id"] for p in pairs_view(config)}
    print(f"{len(records)} verdicts taken from {source}; {len(shown)} of {len(config['pairs'])} pairs on the page")
    if missing := [p for p in config["pairs"] if p not in shown]:
        print("not judged in that run; --prepare-pairs judges them:", ", ".join(missing))
    return 0


def _changed_lines(a: list[str], b: list[str]) -> tuple[set[int], set[int]]:
    """The 1-based lines that differ between two functions, on each side."""
    left: set[int] = set()
    right: set[int] = set()
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag != "equal":
            left.update(range(i1 + 1, i2 + 1))
            right.update(range(j1 + 1, j2 + 1))
    return left, right


def _function_view(row: dict[str, Any], changed: set[int], record: dict[str, Any]) -> dict[str, Any]:
    """One function as the page shows it: its lines, with the ones that differ marked, and the agent's verdict on it."""
    verdict = record.get("verdict") or {}
    answer = verdict.get("is_vulnerable")
    lines = str(row["code"]).splitlines()
    return {
        "lines": [{"n": n, "text": text, "changed": n in changed} for n, text in enumerate(lines, start=1)],
        "verdict": None if answer is None else ("vulnerable" if answer else "benign"),
        "right": answer is not None and bool(answer) == bool(row["gold_is_vulnerable"]),
        "rationale": " ".join(str(verdict.get("rationale") or "").split()),
        "cwe": verdict.get("cwe"),
        "flagged": [
            int(n) for n in verdict.get("vulnerable_lines") or [] if isinstance(n, int) and 1 <= n <= len(lines)
        ],
        "seconds": round(float(record.get("seconds") or 0)),
        "lookups": len([t for t in record.get("trajectory") or [] if isinstance(t, dict) and t.get("tool")]),
    }


def _text(value: Any) -> str:
    """A metadata field as text; PrimeVul writes the word "None" where it has nothing."""
    return "" if value is None or str(value).strip() in ("", "None", "null") else str(value)


def pairs_view(config: dict[str, Any]) -> list[dict[str, Any]]:
    """
    The chosen pairs for the page, in pairs.yaml's order: both functions, the diff, and the agent's two verdicts.

    A pair appears once the agent has judged both of its functions.
    """
    tasks = pair_run_dir(config) / "tasks.json"
    if not PAIRS.is_file() or not tasks.is_file():
        return []
    records = {str(r["task_id"]): r for r in json.loads(tasks.read_text(encoding="utf-8"))}
    meta_path = REPO / config["meta"]
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
    by_pair: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for row in _rows(PAIRS):
        by_pair[str(row.get("pair_id"))].append(row)
    out = []
    for pair_id in config["pairs"]:
        vulnerable = [r for r in by_pair.get(pair_id, []) if r["gold_is_vulnerable"]]
        patched = [r for r in by_pair.get(pair_id, []) if not r["gold_is_vulnerable"]]
        if len(vulnerable) != 1 or len(patched) != 1:
            continue
        vul, fix = vulnerable[0], patched[0]
        rv, rf = records.get(str(vul["id"])), records.get(str(fix["id"]))
        if rv is None or rf is None:
            continue
        changed_vul, changed_fix = _changed_lines(str(vul["code"]).splitlines(), str(fix["code"]).splitlines())
        m = meta.get(str(vul["id"])) or meta.get(str(fix["id"])) or {}
        repo_url = (_text(m.get("repo_url")) or _text(m.get("project_url"))).rstrip("/").removesuffix(".git")
        views = {"vulnerable": _function_view(vul, changed_vul, rv), "patched": _function_view(fix, changed_fix, rf)}
        out.append(
            {
                "id": pair_id,
                "project": _text(m.get("project")),
                "file": _text(m.get("file_name")),
                "commit_url": f"{repo_url}/commit/{_text(m.get('commit_id'))}"
                if repo_url and _text(m.get("commit_id"))
                else None,
                "cwe": vul.get("gold_cwe"),
                "cwe_name": cwe_name(str(vul.get("gold_cwe") or "")),
                "lang": vul.get("lang") or "c",
                **views,
                "right": views["vulnerable"]["right"] and views["patched"]["right"],
                # which function the page shows first, as "A": fixed per pair, so a reload does not reshuffle
                "first": "vulnerable" if int(hashlib.sha256(pair_id.encode()).hexdigest(), 16) % 2 == 0 else "patched",
            }
        )
    return out


# -- the state of the GUI -------------------------------------------------------------------------------------------


class Gui:
    """The current demo run, and the integrations."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.demo: DemoRun | None = None
        self.config = load_integrations()
        self.pairs_config = load_pairs_config()

    def busy(self) -> str | None:
        """What is running: the demo, or nothing."""
        return "demo" if self.demo is not None and not self.demo.done else None

    def start_demo(self, approved_by: str) -> str | None:
        """Start a demo run; the reason if one cannot start now."""
        with self.lock:
            if busy := self.busy():
                return f"a {busy} is running"
            command = [str(REPO / "demo" / "run_demo.sh"), "--approved-by", approved_by[:60] or "GUI visitor"]
            self.demo = DemoRun(command)
        return None

    def integrations(self) -> list[dict[str, Any]]:
        """The integrations whose current result was approved on this machine, for the page; else the shipped ones."""
        local = [integration_view(e, self.config) for e in self.config["integrations"] if approved(e["name"])]
        return local or shipped("integrations")

    def pairs(self) -> list[dict[str, Any]]:
        """The PrimeVul pairs the agent has judged on this machine, for the page; else the shipped ones."""
        return pairs_view(self.pairs_config) or shipped("pairs")


def shipped(kind: str) -> list[dict[str, Any]]:
    """What the page showed on our machine (`integrations` or `pairs`), as written by --snapshot."""
    path = SHIPPED / f"{kind}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []


def snapshot(config: dict[str, Any], pairs_config: dict[str, Any], names: list[str]) -> int:
    """
    Write what the page shows of the named approved integrations, and of the judged pairs, to shipped/.

    Only what the page shows goes there: each finding with its code excerpt, and each pair's two functions with the
    agent's verdicts. The scans' and the agent's own records stay on this machine.
    """
    unknown = [n for n in names if not approved(n)]
    if unknown:
        print(f"not approved on this machine, so not written: {', '.join(unknown)}")
        return 1
    integrations = [integration_view(e, config) for e in config["integrations"] if e["name"] in names]
    pairs = pairs_view(pairs_config)
    SHIPPED.mkdir(exist_ok=True)
    for kind, views in (("integrations", integrations), ("pairs", pairs)):
        text = json.dumps(views, indent=1, ensure_ascii=False) + "\n"
        (SHIPPED / f"{kind}.json").write_text(text, encoding="utf-8")
    shown = ", ".join(i["name"] for i in integrations)
    print(f"{SHIPPED}: {len(integrations)} integrations ({shown}), {len(pairs)} pairs")
    return 0


def model_answers() -> bool:
    """Does the model server generate? One output token, thinking off."""
    body = json.dumps(
        {
            "model": "qwen3.8-flash-next",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "Reply with OK."}],
            "chat_template_kwargs": {"enable_thinking": False},
        }
    ).encode()
    request = urllib.request.Request(
        MODEL_URL + "/chat/completions", data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 - the local model server
            return response.status == 200
    except Exception:  # noqa: BLE001 - down, loading or absent
        return False


def sandbox_exists() -> bool:
    """Does the demo's OpenShell sandbox exist?"""
    try:
        listing = subprocess.run(
            ["openshell", "sandbox", "list"], capture_output=True, text=True, timeout=20, check=False
        )  # noqa: S607
    except (OSError, subprocess.TimeoutExpired):
        return False
    return SANDBOX in listing.stdout


# -- the web server -------------------------------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    gui: Gui

    def log_message(self, *args: Any) -> None:
        """Keep the console quiet: no line per request."""

    def _json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path, root: Path) -> None:
        path = path.resolve()
        if root.resolve() not in path.parents or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", CONTENT_TYPES.get(path.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    def do_GET(self) -> None:  # noqa: N802 - http.server's name
        """The page, its files, the recording, and the read-only API."""
        route = urlparse(self.path).path
        if route == "/":
            self._file(STATIC / "index.html", STATIC)
        elif route.startswith("/static/"):
            self._file(STATIC / route.removeprefix("/static/"), STATIC)
        elif route.startswith("/recording/"):
            self._file(RECORDING / route.removeprefix("/recording/"), RECORDING)
        elif route == "/api/evolution":
            self._file(HERE / "evolution.json", HERE)
        elif route == "/api/status":
            self._json({"model": model_answers(), "sandbox": sandbox_exists(), "busy": self.gui.busy()})
        elif route == "/api/integrations":
            self._json(self.gui.integrations())
        elif route == "/api/pairs":
            self._json(self.gui.pairs())
        elif route == "/api/demo/stream":
            self._stream()
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802 - http.server's name
        """Start the demo, answer its prompt, stop it."""
        route, body = urlparse(self.path).path, self._body()
        demo = self.gui.demo
        if route == "/api/demo/start":
            problem = self.gui.start_demo(str(body.get("approved_by") or ""))
            self._json(
                {"error": problem} if problem else {"ok": True}, HTTPStatus.CONFLICT if problem else HTTPStatus.OK
            )
        elif route == "/api/demo/answer" and demo is not None:
            demo.answer(bool(body.get("approve")))
            self._json({"ok": True})
        elif route == "/api/demo/stop" and demo is not None:
            demo.stop()
            self._json({"ok": True})
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def _stream(self) -> None:
        """The current demo run's output as server-sent events: `out` chunks, `prompt`, `end`."""
        demo = self.gui.demo
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if demo is None:
            self._event("end", {"code": None})
            return
        sent, prompted = 0, False
        try:
            while True:
                with demo.cond:
                    if len(demo.chunks) == sent and not demo.done and demo.awaiting == prompted:
                        demo.cond.wait(timeout=15)
                    chunks, awaiting, done, code = demo.chunks[sent:], demo.awaiting, demo.done, demo.returncode
                sent += len(chunks)
                if chunks:
                    self._event("out", "".join(chunks))
                if awaiting != prompted:
                    prompted = awaiting
                    self._event("prompt", {"awaiting": awaiting})
                if done and not chunks:
                    self._event("end", {"code": code})
                    return
                if not chunks:
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):  # the page went away
            return

    def _event(self, name: str, data: Any) -> None:
        self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
        self.wfile.flush()


def prepare(config: dict[str, Any], rescan: bool, parallel: int) -> int:
    """Scan the integrations with the evolved agent (those not scanned yet, or all with `rescan`)."""
    root = checkout(config)
    names = [e["name"] for e in config["integrations"] if rescan or not result_path(e["name"]).is_file()]
    print(f"haystack-core-integrations at {config['commit'][:7]}: scanning {len(names)} integrations", flush=True)

    def one(name: str) -> None:
        started = time.monotonic()
        code = scan(name, root)
        result = _result(name)
        if result is None or code not in (0, 1):
            summary = f"failed, see {result_path(name).with_suffix('.log')}"
        else:
            summary = f"{len(result['findings'])} findings" + ("" if result.get("complete", True) else ", incomplete")
        print(f"  {name}: {summary} ({time.monotonic() - started:.0f} s)", flush=True)

    with ThreadPoolExecutor(max_workers=max(1, parallel)) as pool:
        list(pool.map(one, names))
    print("Next: hatch run synthetic:gui --review, then --approve the integrations whose findings may be shown.")
    return 0


def review(config: dict[str, Any]) -> int:
    """Print every scanned integration's findings, for the person who decides what the page may show."""
    for entry in config["integrations"]:
        name, result = entry["name"], _result(entry["name"])
        if result is None:
            print(f"== {name}: not scanned")
            continue
        state = "approved" if approved(name) else "NOT approved"
        if not result.get("complete", True):
            state = f"INCOMPLETE ({result.get('error')}), cannot be approved; scan again with --prepare --rescan"
        print(f"== {name}: {len(result['findings'])} findings, {state}")
        known = explanations(result)
        for f in result["findings"]:
            print(f"   {f['path']}:{f['line_start']}-{f['line_end']}  {f['cwe']}  {f['title']}")
            if why := full_explanation(f, known)[0]:
                print(textwrap.indent(textwrap.fill(" ".join(why.split()), 110), "      "))
    print('\nPut integrations on the page: hatch run synthetic:gui --approve NAME [NAME ...] --by "Your Name"')
    return 0


def main(argv: list[str] | None = None) -> int:
    """Serve the page, or prepare, review and approve the integrations' scans."""
    parser = argparse.ArgumentParser(
        prog="gui", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--prepare", action="store_true", help="scan the integrations not scanned yet, then exit")
    parser.add_argument("--rescan", action="store_true", help="with --prepare: scan every integration again")
    parser.add_argument("--parallel", type=int, default=2, help="with --prepare: integrations scanned at once")
    parser.add_argument("--review", action="store_true", help="print every scan's findings, then exit")
    parser.add_argument("--approve", nargs="+", metavar="NAME", help="put these integrations on the page, then exit")
    parser.add_argument("--revoke", nargs="+", metavar="NAME", help="take these integrations off the page, then exit")
    parser.add_argument("--by", default="", help="with --approve: who reviewed the findings")
    parser.add_argument(
        "--prepare-pairs", action="store_true", help="judge the PrimeVul pairs in pairs.yaml, then exit"
    )
    parser.add_argument(
        "--import-pairs", metavar="TASKS_JSON", help="take the pairs' verdicts from an earlier run, then exit"
    )
    parser.add_argument(
        "--snapshot",
        nargs="+",
        metavar="NAME",
        help="write the page's view of these approved integrations, and of the pairs, to shipped/, then exit",
    )
    args = parser.parse_args(argv)
    config = load_integrations()
    if args.snapshot:
        return snapshot(config, load_pairs_config(), args.snapshot)
    if args.prepare:
        return prepare(config, args.rescan, args.parallel)
    if args.prepare_pairs:
        return prepare_pairs(load_pairs_config())
    if args.import_pairs:
        return import_pairs(load_pairs_config(), Path(args.import_pairs))
    if args.review:
        return review(config)
    if args.approve or args.revoke:
        missing = set_approval(args.approve or args.revoke, args.by, approve=bool(args.approve))
        for name in missing:
            print(f"{name}: no finished scan, nothing to approve")
        print(f"on the page: {', '.join(e['name'] for e in config['integrations'] if approved(e['name'])) or 'none'}")
        return 1 if missing else 0
    gui = Gui()
    Handler.gui = gui
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    print(f"gui: http://{args.host}:{args.port}  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if gui.demo is not None:
            gui.demo.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
