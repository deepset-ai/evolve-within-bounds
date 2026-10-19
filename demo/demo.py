# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The live demo: one iteration of the self-improvement loop on the synthetic benchmark, deployed after a person approves.

  python demo/demo.py prepare        before the talk: pre-register the experiment, measure the seed on the demo's pair
  python demo/demo.py run [--yes]    the live run, from a fresh copy of what prepare measured

It is the loop of docs/synthetic.md (`security_agent.optimize.loop.Experiment` with the synthetic task), cut down in
size (demo/demo.yaml): one training pair, one optimizer turn of a few steps, no trial scans; and the optimizer runs
at temperature 0. Every scan, and every line of the optimizer's code, runs inside the OpenShell sandbox. The run
prints:

1. the benchmark, the training pair and the bounds;
2. the starting point: the seed's result on the pair, measured by `prepare`, the pair's planted lines, and the seed's
   trace on the twin where it failed (`traced_side`);
3. the optimizer's turn: what it is given, then one line per tool call as it happens;
4. what the optimizer changed: its reason, and the change as `git diff` shows it;
5. the candidate's measurement on the pair, and whether it clears the gates;
6. the approval: a prompt to approve the candidate if it became the new best (otherwise the agent of our full loop
   run), the deployment into the sandbox;
7. the deployed agent scanning a repository from the validation pairs, which nothing in the loop has seen.

Run it through the scripts next to this file (prepare.sh, run_demo.sh), which check the setup first.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from security_agent.optimize.loop import Experiment, gpu_seconds, label_counts
from security_agent.optimize.proposer import agent_proposer
from security_agent.synthetic.config import REPO_ROOT, load_yaml

HERE = Path(__file__).resolve().parent
CONFIG = HERE / "demo.yaml"
BENCHMARK = "hvbench"
TOLERANCE = 2  # the scorer's line tolerance
FALLBACK = REPO_ROOT / "agents" / "synthetic" / "looped"
DIFF_ROWS = 40  # the diff is cut after this many terminal rows; the whole of it goes to <live_dir>/candidate.diff
STAT_BAR = 40  # the longest `+++--` bar of the diff's summary
# The digests' failure labels, as the audience reads them (security_agent.synthetic.digest).
LABELS = {
    "missed": "reported nothing in the planted file",
    "wrong_lines_near": "reported in the planted file, a few lines off",
    "wrong_lines_far": "reported in the planted file, far from the planted lines",
    "safe_twin_flagged": "flagged the same lines in the fixed twin",
    "reported_then_dropped": "found it, then a later step dropped it",
}

DEMO_NOTE = """

## This turn is a live demonstration
An audience is watching this one turn, so it is short: at most $max_steps tool calls, and `run_tool` and
`trial_scan` are not available. Read what the agent did on the failing training pair (`read_reasoning`), then make one
focused change that addresses what you saw: in the agent's prompt (prompts/system.md), or one small tool if the problem
needs it. Keep the agent's limits as they are: the measurement must finish in a few minutes. Then call
`validate_candidate`, and `submit_candidate` with a one-sentence rationale. Do not start a second idea.
"""

_STYLE = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "green": "\033[32m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "off": "\033[0m",
}
# The diff's line kinds, in git's colours.
DIFF_STYLE: dict[str, tuple[str, ...]] = {
    "meta": ("bold",),
    "hunk": ("cyan",),
    "add": ("green",),
    "del": ("red",),
    "context": (),
}


def paint(text: str, *names: str) -> str:
    """Terminal styles, or none when the output is redirected."""
    if not names or not text or not sys.stdout.isatty():
        return text
    return "".join(_STYLE[name] for name in names) + text + _STYLE["off"]


def rule(label: str) -> str:
    """A labelled separator."""
    width = min(shutil.get_terminal_size(fallback=(100, 24)).columns, 110)
    return paint(f"── {label} " + "─" * max(width - len(label) - 4, 4), "dim")


def section(number: int, title: str) -> None:
    """A numbered section heading."""
    print()
    print(paint(f"=== {number}. {title} ===", "bold"))


def field(name: str, text: str) -> None:
    """One labelled line, indented."""
    print(f"    {paint(f'{name:<11}', 'bold')}{text}")


class Clock:
    """Elapsed time since the run started, and per section."""

    def __init__(self) -> None:
        self.started = time.monotonic()
        self.mark = self.started

    def lap(self) -> str:
        """Time since the last lap, as m:ss."""
        now = time.monotonic()
        seconds, self.mark = now - self.mark, now
        return f"{int(seconds // 60)}:{int(seconds % 60):02d}"

    def total(self) -> str:
        """Time since the start, as m:ss."""
        seconds = time.monotonic() - self.started
        return f"{int(seconds // 60)}:{int(seconds % 60):02d}"


def load_config() -> dict[str, Any]:
    """The demo's settings."""
    return yaml.safe_load(CONFIG.read_text(encoding="utf-8"))


def experiment(config: dict[str, Any], run_dir: Path, observer: Any = None, log: Any = None) -> tuple[Experiment, Any]:
    """The demo's experiment in `run_dir`, with its task (scans in the sandbox) and the cut-down optimizer."""
    from string import Template

    from security_agent.synthetic.sandbox import OpenShell
    from security_agent.synthetic.task import SyntheticTask

    name, pair = config["train_pair"].split("/", 1)
    train = {name: [pair]}
    task = SyntheticTask(
        model_config=config["model_config"],
        concurrency=int(config["concurrency"]),
        sandbox=OpenShell(config["sandbox"]),
        log=log or (lambda _line: None),
    )
    system = task.system_prompt(task.prompt_values(config, train))
    system += Template(DEMO_NOTE).substitute(max_steps=config["proposer"]["max_steps"])
    exp = Experiment(
        run_dir,
        config=config,
        train=train,
        reference=REPO_ROOT / config["reference"],
        proposer=agent_proposer(task.model, config["proposer"], system, observer=observer),
        task=task,
        log=log or (lambda _line: None),
    )
    # A live turn has no time for trial scans or for running code on examples.
    for option in ("trial_runner", "example_runner"):
        exp.workspace_options.pop(option, None)
    return exp, task


def _per_repo_minutes(m: Any, rules: dict[str, Any]) -> float:
    from security_agent.optimize.loop import Rules

    return gpu_seconds(m.cost, Rules(**rules)) / 60 / max(1, m.instances)


def describe(m: Any, rules: dict[str, Any], reference: Any = None) -> str:
    """Pairs right, findings and GPU time of a measurement, against the reference when there is one."""
    text = f"{m.right}/{m.pairs} pairs right"
    if reference is not None and m.right != reference.right:
        change = m.right - reference.right
        text += paint(f" ({change:+d})", "green" if change > 0 else "red")
    minutes = _per_repo_minutes(m, rules)
    return f"{text} · {plural(m.findings, 'finding')} · {minutes:.1f} estimated GPU-minutes per repository"


def cmd_prepare(_args: argparse.Namespace) -> int:
    """Pre-register the demo's experiment and measure the seed on its pair."""
    config = load_config()
    run_dir = REPO_ROOT / config["prepared_dir"]
    if run_dir.exists():
        shutil.rmtree(run_dir)
    exp, _ = experiment(config, run_dir, log=lambda line: print(paint(f"  {line}", "dim"), flush=True))
    m = exp.prepare()
    print(f"seed on {config['train_pair']}: {describe(m, config['rules'])}")
    print(f"failure labels: {json.dumps(label_counts(m.digests))}")
    if m.right == m.pairs:
        print(paint("note: the seed gets the pair right, so the optimizer has no failure to work on", "red"))
    else:
        from security_agent.synthetic.bench.adapters import load_benchmark
        from security_agent.synthetic.bench.pairs import load_pairs

        print("what section 2 of the demo will show:")
        show_start(m, load_pairs(load_benchmark(config["train_pair"].split("/", 1)[0])))
    print(f"prepared {run_dir}; run the demo with demo/run_demo.sh")
    return 0


def plural(count: int, noun: str) -> str:
    """`1 finding`, `2 findings`."""
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _short(value: Any, limit: int = 70) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


class TurnPrinter:
    """Prints the optimizer's tool calls as they happen."""

    def __init__(self) -> None:
        self.started = time.monotonic()
        self.rationale = ""
        self.traced: tuple[str, str] | None = None  # the pair and twin whose trace section 2 showed

    def __call__(self, name: str, arguments: dict[str, Any], result: str) -> None:
        """One tool call: when, which tool, on what, and how it went."""
        elapsed = time.monotonic() - self.started
        try:
            data = json.loads(result)
        except (TypeError, ValueError):
            data = {}
        target = ""
        if name in ("read_file", "edit_file", "write_file", "delete_file"):
            target = arguments.get("path", "")
        elif name == "read_reasoning":
            side = str(arguments.get("side", "vulnerable"))
            target = f"{arguments.get('example', '')}, {SIDE_NAMES.get(side, side).removeprefix('the ')}"
        outcome = ""
        if name == "read_reasoning" and data.get("ok"):
            steps = plural(int(data.get("steps") or 0), "step")
            seen = self.traced == (str(arguments.get("example", "")).strip(), str(arguments.get("side", "vulnerable")))
            outcome = f"the trace above, in full ({steps})" if seen else steps
        elif name == "edit_file" and data.get("ok"):
            added = len(str(arguments.get("new", "")).splitlines()) - len(str(arguments.get("old", "")).splitlines())
            outcome = f"{added:+d} lines"
        elif name == "write_file" and data.get("ok"):
            outcome = f"{len(str(arguments.get('content', '')).splitlines())} lines"
        elif name == "validate_candidate":
            errors = data.get("errors") or []
            count = f"{len(errors)} problem" + ("" if len(errors) == 1 else "s")
            outcome = "valid" if data.get("valid") else f"{count}: " + _short(errors[0] if errors else "", 60)
        elif name == "submit_candidate":
            self.rationale = str(arguments.get("rationale", ""))
            outcome = "submitted" if data.get("ok") else "refused: " + _short(data.get("error") or result, 60)
        elif name == "finish":
            outcome = "finished: " + _short(arguments.get("reason", ""), 60)
        if data.get("ok") is False and not outcome:
            outcome = "refused: " + _short(data.get("error") or "", 60)
        if result.startswith(("_Refusal", "ValueError")) and not outcome:
            outcome = "refused"
        colour = "red" if outcome.startswith("refused") or " problem" in outcome else "green"
        print(
            f"    {paint(f'{int(elapsed // 60)}:{int(elapsed % 60):02d}', 'dim')}  {paint(f'{name:<19}', 'cyan')}"
            f"{_short(target, 48):<50}{paint(outcome, colour) if outcome else ''}",
            flush=True,
        )


def _diff_files(diff: str) -> list[tuple[str, list[str]]]:
    """The files of a candidate's diff (`security_agent.optimize.candidate.diff`): each path, with its hunks' lines."""
    files: list[tuple[str, list[str]]] = []
    lines = diff.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].startswith("--- parent/") and i + 1 < len(lines) and lines[i + 1].startswith("+++ candidate/"):
            files.append((lines[i + 1].removeprefix("+++ candidate/"), []))
            i += 2
            continue
        if files:
            files[-1][1].append(lines[i])
        i += 1
    return files


def git_diff(diff: str) -> list[tuple[str, str]]:
    """The diff as `git diff` prints it, with each line's kind: a/ and b/ paths, new and deleted files marked."""
    out: list[tuple[str, str]] = []
    for path, body in _diff_files(diff):
        out.append(("meta", f"diff --git a/{path} b/{path}"))
        first = body[0] if body else ""
        if first.startswith("@@ -0,0 "):
            out += [("meta", "new file mode 100644"), ("meta", "--- /dev/null"), ("meta", f"+++ b/{path}")]
        elif " +0,0 @@" in first:
            out += [("meta", "deleted file mode 100644"), ("meta", f"--- a/{path}"), ("meta", "+++ /dev/null")]
        else:
            out += [("meta", f"--- a/{path}"), ("meta", f"+++ b/{path}")]
        for line in body:
            kind = "hunk" if line.startswith("@@") else {"+": "add", "-": "del"}.get(line[:1], "context")
            out.append((kind, line))
    return out


def diff_stat(diff: str) -> list[str]:
    """The diff as `git diff --stat` sums it up: a line per file, then the totals."""
    rows = [
        (path, sum(line.startswith("+") for line in body), sum(line.startswith("-") for line in body))
        for path, body in _diff_files(diff)
    ]
    if not rows:
        return []
    most = max(added + removed for _, added, removed in rows)
    scale = min(1.0, STAT_BAR / most)
    width, digits = max(len(path) for path, _, _ in rows), len(str(most))
    lines = []
    for path, added, removed in rows:
        plus = max(1, round(added * scale)) if added else 0
        minus = max(1, round(removed * scale)) if removed else 0
        bar = paint("+" * plus, "green") + paint("-" * minus, "red")
        lines.append(f"{path:<{width}} | {added + removed:>{digits}} {bar}")
    added, removed = sum(row[1] for row in rows), sum(row[2] for row in rows)
    totals = [f"{plural(len(rows), 'file')} changed"]
    totals += [f"{plural(added, 'insertion')}(+)"] if added else []
    totals += [f"{plural(removed, 'deletion')}(-)"] if removed else []
    return [*lines, ", ".join(totals)]


def _wrap(kind: str, text: str, width: int) -> list[str]:
    """One diff line as terminal rows; a wrapped line goes on under its first character."""
    if len(text) <= width:
        return [text]
    if kind in ("add", "del", "context"):
        rows = textwrap.wrap(text[1:], width - 1, replace_whitespace=False, break_on_hyphens=False) or [""]
        return [text[:1] + rows[0]] + [" " + row for row in rows[1:]]
    return textwrap.wrap(text, width) or [text]


def print_diff(lines: list[tuple[str, str]], full: Path) -> None:
    """The diff in git's colours, wrapped to the terminal and cut after `DIFF_ROWS` rows."""
    width = shutil.get_terminal_size(fallback=(100, 24)).columns - 5
    rows = 0
    for n, (kind, text) in enumerate(lines):
        pieces = _wrap(kind, text, width)
        if rows + len(pieces) > DIFF_ROWS:
            rest = plural(len(lines) - n, "more line")
            print(paint(f"    … {rest}, the whole diff in {full.relative_to(REPO_ROOT)}", "dim"))
            return
        for piece in pieces:
            print(f"    {paint(piece, *DIFF_STYLE[kind])}")
        rows += len(pieces)


# -- the seed's trace on the pair --------------------------------------------------------------------------------------

# Failure modes of the vulnerable repository (security_agent.synthetic.digest). While one of them holds, the trace
# follows the vulnerable repository; a flagged fixed twin alone is traced in the fixed twin.
VULNERABLE_MODES = ("reported_then_dropped", "missed", "wrong_lines_far", "wrong_lines_near")
SIDE_NAMES = {"vulnerable": "the vulnerable repository", "safe_twin": "the fixed twin"}
TRACE_STEPS = 8  # longer traces keep their first step, the quoted step, the reports and the last step
QUOTE_CHARS = 220
_WORD = re.compile(r"[a-z_][a-z0-9_]{3,}")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CONTRAST = re.compile(r"\b(but|however|yet|although|though|not sufficient|not enough)\b", re.IGNORECASE)
_COMMON = {"self", "return", "none", "true", "false", "import", "from", "else", "elif", "with", "for", "while", "str"}


def traced_side(labels: list[str]) -> str:
    """The twin whose trace shows the failure: the vulnerable repository whenever it failed, else the fixed twin."""
    return "vulnerable" if any(label in VULNERABLE_MODES for label in labels) else "safe_twin"


_PAIR = re.compile(r'"(\w+)":\s*("(?:[^"\\]|\\.)*"|-?\d+)')


def _args(call: dict[str, Any]) -> dict[str, Any]:
    """A tool call's arguments. The record keeps their JSON cut at 800 characters; then the complete pairs count."""
    raw = str(call.get("args") or "{}")
    try:
        args = json.loads(raw)
        return args if isinstance(args, dict) else {}
    except ValueError:
        pass
    found: dict[str, Any] = {}
    for key, value in _PAIR.findall(raw):
        found.setdefault(key, json.loads(value))
    return found


def _steps(trajectory: list[dict[str, Any]]) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    """The agent's steps: each of its messages, with the results of the tool calls it made."""
    steps: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    for message in trajectory:
        if message.get("role") == "assistant":
            steps.append((message, []))
        elif steps and message.get("results"):
            steps[-1][1].extend(message["results"])
    return steps


def _fill_reports(steps: list[Any], reported: list[dict[str, Any]]) -> None:
    """
    Complete the report_finding calls whose cut arguments lack the path or the lines, from the reported findings.

    The findings are in the order of the calls; a finding is used only when its title matches the call's, if it has one.
    """
    findings = iter(reported)
    for message, _ in steps:
        for call in message.get("calls") or []:
            if call.get("tool") != "report_finding":
                continue
            known, args = next(findings, None), _args(call)
            title = str(args.get("title", ""))[:30]
            matches = not title or str(known.get("title", ""))[:30] == title if known else False
            if known and matches and not (args.get("path") and args.get("line_start")):
                call["args"] = json.dumps({**known, **{k: v for k, v in args.items() if v not in (None, "")}})


def _gap(args: dict[str, Any], lines: list[int]) -> int:
    start = int(args.get("line_start") or 0)
    end = int(args.get("line_end") or start)
    return max(lines[0] - end, start - lines[1], 0)


def _mark(args: dict[str, Any], side: str, path: str, lines: list[int]) -> str:
    """Where a reported finding lies, against the planted lines of this twin."""
    if args.get("path") != path:
        return paint("another file", "dim")
    gap = _gap(args, lines)
    if gap <= TOLERANCE:
        return paint("✗ the fixed lines", "red") if side == "safe_twin" else paint("✓ the planted lines", "green")
    if side == "safe_twin":
        return paint("elsewhere in the file", "dim")
    return paint(f"✗ {plural(gap, 'line')} from the planted lines", "red")


def _sentences(text: str) -> list[str]:
    """The text's sentences. Code spans lose their backticks, unless they hold only punctuation, like `"`."""
    text = re.sub(r"`([^`]*)`", lambda m: m.group(1) if re.search(r"\w", m.group(1)) else m.group(0), text)
    return re.split(r"(?<=[.!?])\s+", " ".join(text.split()))


def _premise(sentence: str) -> str:
    """The point a contrast answers: the last clause of the sentence before it, without its leading conjunction."""
    clause = re.sub(r"^(so|and|but|which|thus|hence)\s+", "", sentence.rsplit(", ", 1)[-1], flags=re.IGNORECASE)
    if len(clause) > 90:
        clause = clause[-90:].split(" ", 1)[-1]
    return clause if clause == sentence else f"… {clause}"


def _control(target: dict[str, Any]) -> set[str]:
    """Stems of what the fix added: the identifiers in the fixed twin's planted lines that the vulnerable ones lack."""
    fixed, vulnerable = (
        {m.lower() for _, text, hit in rows if hit for m in _IDENT.findall(text)}
        for rows in (target["baseline_excerpt"], target["mutant_excerpt"])
    )
    return {part[:5] for name in fixed - vulnerable for part in name.split("_") if len(part) >= 5}


def _quote(steps: list[Any], upto: int, words: set[str], latest: bool, control: set[str]) -> tuple[int, str] | None:
    """
    The reasoning sentence, up to step `upto`, that best shows how the failure came about.

    It shares the most `words`; when `control` is given (the fixed twin), naming the fix's control counts double, and
    so does a contrast to it ("…, but …"). Ties go to the latest sentence when `latest`, else to the shortest. A
    sentence that opens with the contrast keeps its premise.
    """
    best: tuple[tuple[int, int, int], int, str] | None = None
    for i, (message, _) in enumerate(steps[: upto + 1]):
        sentences = _sentences(str(message.get("reasoning") or ""))
        for j, sentence in enumerate(sentences):
            lowered = sentence.lower()
            score = len(words & set(_WORD.findall(lowered)))
            if control and any(stem in lowered for stem in control):
                score += 2 + (2 if _CONTRAST.search(sentence) else 0)
            if not score:
                continue
            if lowered.startswith(("however", "but ", "yet ", "still")) and j:
                sentence = f"{_premise(sentences[j - 1])} {sentence}"
            key = (score, i if latest else 0, -len(sentence))
            if best is None or key > best[0]:
                best = (key, i, sentence)
    if best is None:
        return None
    text = best[2] if len(best[2]) <= QUOTE_CHARS else best[2][: QUOTE_CHARS - 1] + "…"
    return best[1], text


def _focus(
    steps: list[Any], side: str, labels: list[str], target: dict[str, Any]
) -> tuple[int, set[str], bool, set[str]]:
    """The step the quote leads up to, the words it should share, whether the latest match wins, the fix's control."""
    path, lines = target["path"], target["mutant_lines" if side == "vulnerable" else "baseline_lines"]
    reports = [
        (i, args)
        for i, (message, _) in enumerate(steps)
        for args in (_args(c) for c in message.get("calls") or [] if c.get("tool") == "report_finding")
        if args.get("path") == path
    ]
    if reports and (side == "safe_twin" or "missed" not in labels):
        step, args = min(reports, key=lambda r: _gap(r[1], lines))  # the report on, or nearest to, the planted lines
        control = _control(target) if side == "safe_twin" else set()
        return step, set(_WORD.findall(str(args.get("title", "")).lower())), False, control
    code = " ".join(text for _, text, hit in target["mutant_excerpt"] if hit)
    return len(steps) - 1, set(_WORD.findall(code.lower())) - _COMMON, True, set()


def _rows(message: dict[str, Any], results: list[dict[str, Any]], side: str, target: dict[str, Any]) -> list[Any]:
    """One step as rows of (tool, detail): file reads grouped, each code run and each report on its own."""
    path, lines = target["path"], target["mutant_lines" if side == "vulnerable" else "baseline_lines"]
    calls = message.get("calls") or []
    results = results + [{}] * (len(calls) - len(results))
    rows: list[list[str]] = []
    for call, result in zip(calls, results, strict=False):
        tool, args = str(call.get("tool")), _args(call)
        if tool == "read_file":
            name = PurePosixPath(str(args.get("path", "?"))).name
            if rows and rows[-1][0] == "read_file":
                rows[-1][1] += f" · {name}"
            else:
                rows.append(["read_file", name])
        elif tool == "run_python":
            code = (str(args.get("code", "")).strip().splitlines() or [""])[0]
            output = [line for line in str(result.get("result", "")).splitlines() if line.strip()]
            rows.append(["run_python", f"{_short(code, 40)}  →  {_short(output[-1] if output else 'no output', 60)}"])
        elif tool == "report_finding":
            start = args.get("line_start")
            span = f"lines {start}-{args.get('line_end', start)}  " if start is not None else ""
            detail = f"{span}{args.get('cwe', '')}  {_short(args.get('title', ''), 50)}"
            mark = _mark(args, side, path, lines) if args.get("path") else ""
            rows.append(["report", f"{detail}   {mark}".rstrip()])
        else:
            rows.append([tool, _short(next(iter(args.values()), ""), 60)])
    if not calls and message.get("text"):
        sentences = _sentences(re.sub(r"\*\*[^*]+\*\*", "", str(message["text"])))
        rows.append(["answers", f"“{_short(sentences[0] if sentences else '', 80)}”"])
    return rows


def _print_row(number: str, tool: str, detail: str, width: int) -> None:
    indent = 6 + 4 + 13
    if tool == "read_file":
        detail = _short(detail, max(30, width - indent))
    pieces = textwrap.wrap(detail, max(30, width - indent)) if tool == "thinks" else [detail]
    print(f"      {number:>2}  {paint(f'{tool:<13}', 'cyan')}{pieces[0] if pieces else ''}")
    for piece in pieces[1:3]:
        print(f"{'':{indent}}{piece}")


def _print_pair(target: dict[str, Any]) -> None:
    """The planted lines in the vulnerable repository, and the same lines in the fixed twin."""
    lo, hi = target["mutant_lines"]
    field("the pair", f"{target['path']}, " + (f"lines {lo}-{hi}" if hi != lo else f"line {lo}"))
    for name, rows, colour in (
        ("vulnerable", target["mutant_excerpt"], "red"),
        ("fixed", target["baseline_excerpt"], "green"),
    ):
        planted = [(n, text) for n, text, hit in rows if hit][:4]
        code = textwrap.dedent("\n".join(text for _, text in planted)).splitlines()
        for i, ((n, _), text) in enumerate(zip(planted, code, strict=False)):
            print(f"      {name if i == 0 else '':<11}{paint(f'{n:>4} │', 'dim')} {paint(_short(text, 84), colour)}")


def _print_trace(steps: list[Any], side: str, labels: list[str], target: dict[str, Any]) -> None:
    """The agent's steps, with the quoted reasoning; a long trace keeps its first, quoted, reporting and last steps."""
    quote_step, words, latest, control = _focus(steps, side, labels, target)
    quote = _quote(steps, quote_step, words, latest, control)
    reports = {
        i
        for i, (message, _) in enumerate(steps)
        for c in message.get("calls") or []
        if c.get("tool") == "report_finding"
    }
    keep = {0, len(steps) - 1, *reports, *([quote[0]] if quote else [])}
    for i in range(len(steps)):
        if len(keep) >= TRACE_STEPS:
            break
        keep.add(i)
    width = shutil.get_terminal_size(fallback=(100, 24)).columns - 1
    skipped = 0
    for i, (message, results) in enumerate(steps):
        if i not in keep:
            skipped += 1
            continue
        if skipped:
            print(f"          {paint('… ' + plural(skipped, 'more step'), 'dim')}")
            skipped = 0
        number = str(i + 1)
        if quote and quote[0] == i:
            _print_row(number, "thinks", f"“{quote[1]}”", width)
            number = ""
        for tool, detail in _rows(message, results, side, target):
            _print_row(number, tool, detail, width)
            number = ""


def _print_other_twin(side: str, labels: list[str], target: dict[str, Any]) -> None:
    """One line on the twin the trace does not follow, and where a found defect was lost."""
    other = "safe_twin" if side == "vulnerable" else "vulnerable"
    if other == "vulnerable":
        hits = [f for f in target["reported_mutant"] if _gap(f, target["mutant_lines"]) <= TOLERANCE]
        if hits:
            found = f"lines {hits[0]['line_start']}-{hits[0]['line_end']} ({hits[0].get('cwe')})"
            print(f"    on {SIDE_NAMES[other]} it reported {found}  {paint('✓', 'green')}")
    elif "safe_twin_flagged" in labels and target["reported_baseline"]:
        f = target["reported_baseline"][0]
        found = f"lines {f['line_start']}-{f['line_end']} ({f.get('cwe')})"
        print(f"    on {SIDE_NAMES[other]} it also flagged {found}  {paint('✗', 'red')}")
    else:
        print(f"    on {SIDE_NAMES[other]} it reported nothing at those lines  {paint('✓', 'green')}")
    if "reported_then_dropped" in labels:
        dropped = next((s["component"] for s in target.get("steps", []) if s["received"] and not s["passed"]), None)
        later = f"the pipeline step {dropped}" if dropped else "the final normalizing step"
        print(f"    {later} dropped or moved the finding on the planted lines")


def show_start(reference: Any, pairs: dict[str, dict[str, Any]]) -> tuple[str, str] | None:
    """
    The pair's planted lines in both twins, and the seed's trace on the twin where it failed (`traced_side`).

    Returns the traced pair and side, so the optimizer's turn can point back to it.
    """
    from security_agent.synthetic import measure as measuring

    if not reference.digests:
        return None
    digest = reference.digests[0]
    target, labels = digest["targets"][0], digest["labels"]
    side = traced_side(labels)
    benchmark, pair_id = digest["key"].split("/", 1)
    print()
    _print_pair(target)
    instance = pairs[pair_id]["mutant_instance_id" if side == "vulnerable" else "baseline_instance_id"]
    agent = (measuring.record(reference, benchmark, instance) or {}).get("agent") or {}
    steps = _steps(agent.get("trajectory") or [])
    _fill_reports(steps, agent.get("reported") or [])
    stop = agent.get("stop")
    how = "" if stop in (None, "answered") else (", stopped at the step limit" if stop == "max_steps" else f", {stop}")
    print()
    print(f"    {paint(f'the seed on {SIDE_NAMES[side]}', 'bold')}: {plural(len(steps), 'step')}{how}")
    if steps:
        _print_trace(steps, side, labels, target)
    else:
        print("      no conversation was kept")
    _print_other_twin(side, labels, target)
    return digest["key"], side


def show_change(outcome: Any, full: Path) -> None:
    """Why the optimizer made the change, and the change as git shows it; the whole diff is written to `full`."""
    reason = textwrap.wrap(" ".join(outcome.rationale.split()), width=96) or [""]
    field("why", reason[0])
    for line in reason[1:5]:
        print(f"{'':15}{line}")
    stat = diff_stat(outcome.diff)
    field("changed", stat[0] if stat else "nothing")
    for line in stat[1:]:
        print(f"{'':15}{line}")
    lines = git_diff(outcome.diff)
    full.write_text("".join(f"{text}\n" for _, text in lines), encoding="utf-8")
    print()
    print_diff(lines, full)


def _approve(candidate: Path, sandbox: Any, assume_yes: bool) -> bool:
    """The contract, the contract test in the sandbox, and a person's approval."""
    from security_agent.optimize.candidate import candidate_id
    from security_agent.synthetic.agent import check_candidate

    if problems := check_candidate(candidate):
        print(paint("    breaks the contract: " + "; ".join(problems), "red"))
        return False
    if problems := sandbox.contract_test(candidate):
        print(paint("    fails the contract test in the sandbox: " + "; ".join(problems), "red"))
        return False
    field("checked", "the contract, and the contract test of its code inside the sandbox")
    question = f"    Deploy {candidate.name} into the sandbox '{sandbox.name}'? Type 'yes' to approve: "
    if assume_yes:
        print(question + "yes" + paint(f"  (given in advance with --yes; {candidate_id(candidate)})", "dim"))
        return True
    return input(question).strip() == "yes"


def _scan(config: dict[str, Any], sandbox: Any, model: dict[str, Any]) -> None:
    """The deployed agent scans the demo's repository; its findings, with the planted defect marked."""
    from security_agent.synthetic.bench.adapters import load_benchmark
    from security_agent.synthetic.bench.pairs import load_pairs, pair_targets
    from security_agent.synthetic.staging import stage

    bench = load_benchmark(BENCHMARK)
    bench.prepare()
    instance = next(i for i in bench.instances() if i.instance_id == config["scan_instance"])
    pair = next((p for p in load_pairs(bench).values() if p.get("mutant_instance_id") == instance.instance_id), None)
    targets = pair_targets(pair) if pair else []
    field("repository", f"{instance.instance_id} ({pair['repository'] if pair else 'unknown'}), a validation pair")
    staged = stage(Path(instance.path))
    try:
        result = sandbox.scan_deployed(staged, model)
    finally:
        staged.cleanup()
    found = False
    for f in result.findings:
        planted = any(
            f.path == t["path"]
            and f.line_start <= t["mutant_line_end"] + TOLERANCE
            and f.line_end >= t["mutant_line_start"] - TOLERANCE
            for t in targets
        )
        found = found or planted
        mark = paint("  ← the planted defect", "green", "bold") if planted else ""
        print(f"    {f.path}:{f.line_start}-{f.line_end}  {f.cwe}  {_short(f.title, 60)}{mark}")
    if not result.findings:
        print("    no findings")
    status = "" if result.complete else paint(f" (incomplete: {result.error})", "red")
    verdict = paint("found the planted defect", "green") if found else paint("missed the planted defect", "red")
    field("result", f"{plural(len(result.findings), 'finding')}, {verdict}{status}")


def _rank(exp: Experiment, outcome: Any, reference: Any) -> str:
    """Why the candidate is, or is not, the new best: the loop's rank, in words."""
    m = outcome.score
    if exp.best_id != outcome.candidate_id:
        return paint("; not better than the seed, which stays the best", "dim")
    if m.right > reference.right:
        why = "more pairs right"
    elif m.findings < reference.findings:
        why = "as many pairs right, fewer findings"
    else:
        why = "as many pairs right, less GPU time"
    return paint(f"  ← the new best: {why}", "cyan", "bold")


def cmd_run(args: argparse.Namespace) -> int:  # noqa: PLR0915 - the demo, section by section
    """The live demo."""
    from security_agent.synthetic.sandbox import OpenShell

    # The turn's lines show every tool call, refusal and stop; Haystack's warnings about them would only repeat them.
    logging.getLogger("haystack").setLevel(logging.CRITICAL)
    config = load_config()
    prepared = REPO_ROOT / config["prepared_dir"]
    if not (prepared / "journal.jsonl").is_file():
        print("the demo is not prepared: demo/prepare.sh", file=sys.stderr)
        return 2
    live = REPO_ROOT / config["live_dir"]
    if live.exists():
        shutil.rmtree(live)
    shutil.copytree(prepared, live)
    clock = Clock()
    rules = config["rules"]
    name, pair_id = config["train_pair"].split("/", 1)

    turn = TurnPrinter()
    state: dict[str, Any] = {}

    def log(line: str) -> None:
        if line.startswith("[turn 0] candidate"):
            took = paint(f"(the turn took {clock.lap()})", "dim")
            section(4, f"what the optimizer changed  {took}")
            show_change(exp.outcomes[-1], live / "candidate.diff")
            section(5, "measuring the candidate on the training pair, in the sandbox")
            clock.lap()
            state["measuring"] = True
        elif line.startswith("[turn 0] no candidate"):
            print(paint(f"    {line}", "red"))
        elif state.get("measuring") and "hvbench part" in line:
            state["parts"] = state.get("parts", 0) + 1
            print(paint(f"    {line.strip()}", "dim"), flush=True)
        elif state.get("measuring") and f"after part {state.get('parts', 0)}:" in line:
            print(paint(f"    {line.strip()}", "dim"), flush=True)

    exp, _ = experiment(config, live, observer=turn, log=log)
    reference = exp.prepare()

    from security_agent.synthetic.bench.adapters import load_benchmark
    from security_agent.synthetic.bench.pairs import load_pairs

    pairs = load_pairs(load_benchmark(name))
    pair = pairs[pair_id]
    section(1, "the benchmark, the agent and the bounds")
    field("benchmark", "50 pairs of small Haystack component repositories: one with a planted vulnerability, one fixed")
    field("pair", f"{pair_id}: {pair.get('title', '')} ({pair.get('cwe', '')}), the one training pair")
    model = load_yaml(config["model_config"])["model"]
    field("agent", f"{config['reference']}: a Haystack Agent on {model}, deliberately weak")
    field(
        "bounds", f"every scan and the optimizer's code run in the OpenShell sandbox '{config['sandbox']}'; fixed gates"
    )

    section(2, "the starting point, measured before the demo")
    field("seed", describe(reference, rules))
    for label, count in label_counts(reference.digests).items():
        field("failure", f"{LABELS.get(label, label)}" + (f" ({count} pairs)" if count > 1 else ""))
    turn.traced = show_start(reference, pairs)

    section(3, f"one turn of the optimizer, live (at most {config['proposer']['max_steps']} tool calls)")
    from security_agent.optimize.candidate import files

    field("it gets", f"the agent's files: {', '.join(files(REPO_ROOT / config['reference']))}")
    print(f"{'':15}the failure above: the pair's lines, what the seed reported there, a summary of its steps")
    print(f"{'':15}the seed's whole conversation on either twin, when it asks for it (read_reasoning)")
    field("it may", "change the prompts and the pipeline, and add tools; it never sees the validation pairs")
    if args.pause and sys.stdin.isatty():
        input(paint("    press Enter to start the optimizer's turn ", "dim"))
    clock.lap()
    exp.run()

    outcome = exp.outcomes[-1] if exp.outcomes else None
    if outcome is None:
        print(paint("    no candidate was submitted", "red"))
    elif outcome.score is None:
        print(paint(f"    the candidate could not be measured: {outcome.failure or 'no result'}", "red"))
    else:
        field("measured", describe(outcome.score, rules, reference))
        if outcome.gates:
            field("verdict", paint("gated: " + "; ".join(outcome.gates), "red"))
        else:
            field("verdict", paint("cleared every gate", "green") + _rank(exp, outcome, reference))
    took = "measurement" if state.get("measuring") else "the turn"
    print(paint(f"    ({took} took {clock.lap()})", "dim"))

    section(6, "a person approves, then it is deployed into the sandbox")
    sandbox = OpenShell(config["sandbox"])
    # Only a candidate that became the new best is offered; otherwise the agent of our full loop run.
    if outcome is not None and outcome.score is not None and not outcome.gates and exp.best_id == outcome.candidate_id:
        candidate = Path(outcome.directory)
    else:
        if outcome is None or outcome.score is None:
            why = "no candidate was measured"
        elif outcome.gates:
            why = "the candidate did not clear the gates"
        else:
            why = "the candidate is not better than the seed"
        candidate = FALLBACK
        print(f"    {why}; offering the agent our full loop run produced instead")
    field("candidate", str(candidate.relative_to(REPO_ROOT)))
    if not _approve(candidate, sandbox, args.yes):
        print("    not deployed")
        return 1
    from security_agent.optimize.candidate import candidate_id

    sandbox.deploy(
        candidate,
        {
            "candidate_id": candidate_id(candidate),
            "source": str(candidate),
            "approved_by": args.approved_by,
            "approved_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        },
    )
    field("deployed", f"{candidate_id(candidate)} into '{config['sandbox']}', with the approval recorded")
    print(paint(f"    (approval and deployment took {clock.lap()})", "dim"))

    section(7, "the deployed agent scans a repository it has never seen, inside the sandbox")
    _scan(config, sandbox, load_yaml(config["model_config"]))
    print(paint(f"    (scan took {clock.lap()})", "dim"))
    print()
    print(rule(f"done in {clock.total()} · experiment {live.relative_to(REPO_ROOT)}"))
    return 0


def main(argv: list[str] | None = None) -> int:
    """`prepare` or `run`."""
    parser = argparse.ArgumentParser(
        prog="demo", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare", help="before the talk: measure the seed on the demo's pair").set_defaults(
        handler=cmd_prepare
    )
    run = sub.add_parser("run", help="the live demo")
    run.add_argument("--yes", action="store_true", help="approve the deployment without asking (rehearsals)")
    run.add_argument("--approved-by", default="", help="who approves, for the deployment record")
    run.add_argument("--pause", action="store_true", help="wait for Enter before the optimizer's turn starts")
    run.set_defaults(handler=cmd_run)
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
