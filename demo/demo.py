# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The live demo: one iteration of the self-improvement loop on the synthetic benchmark, deployed after a person approves.

  python demo/demo.py prepare        before the talk: pre-register the experiment, measure the seed on the demo's pair
  python demo/demo.py run [--yes]    the live run, from a fresh copy of what prepare measured

It is the loop of docs/synthetic.md (`security_agent.optimize.loop.Experiment` with the synthetic task), cut down in
size only (demo/demo.yaml): one training pair, one optimizer turn of a few steps, no trial scans. Every scan, and every
line of the optimizer's code, runs inside the OpenShell sandbox. The run prints:

1. the benchmark, the training pair and the bounds;
2. the starting point: the seed's result on the pair, measured by `prepare`;
3. the optimizer's turn, one line per tool call as it happens;
4. the candidate's measurement on the pair, and whether it clears the gates;
5. the approval: what changed, a prompt to approve it, the deployment into the sandbox;
6. the deployed agent scanning a repository from the validation pairs, which nothing in the loop has seen.

Run it through the scripts next to this file (prepare.sh, run_demo.sh), which check the setup first.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path
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


def paint(text: str, *names: str) -> str:
    """Terminal styles, or none when the output is redirected."""
    if not sys.stdout.isatty():
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
            target = f"{arguments.get('example', '')} ({arguments.get('side', 'vulnerable')})"
        outcome = ""
        if name == "edit_file" and data.get("ok"):
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


def _diff_summary(diff: str) -> tuple[list[str], list[str]]:
    """Per file `path +a -r`, and a few of the lines the candidate added."""
    counts: dict[str, list[int]] = {}
    added_lines: list[str] = []
    current = ""
    for line in diff.splitlines():
        if line.startswith("+++ "):
            current = line[4:].removeprefix("candidate/")
            counts.setdefault(current, [0, 0])
        elif line.startswith("--- "):
            continue
        elif line.startswith("+") and current:
            counts[current][0] += 1
            if line[1:].strip() and len(added_lines) < 4:
                added_lines.append(line[1:].strip())
        elif line.startswith("-") and current:
            counts[current][1] += 1
    summary = [f"{path} +{a} -{r}" for path, (a, r) in counts.items() if path != "/dev/null"]
    return summary, added_lines


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
            section(4, f"measuring the candidate on the training pair, in the sandbox  {took}")
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

    pair = load_pairs(load_benchmark(name))[pair_id]
    section(1, "the benchmark, the agent and the bounds")
    field("benchmark", "50 pairs of small Haystack component repositories: one with a planted vulnerability, one fixed")
    field("pair", f"{pair_id}: {pair.get('title', '')} ({pair.get('cwe', '')}), the one training pair")
    field("agent", f"{config['reference']}: a Haystack Agent on Qwen3.8 Flash-Next, deliberately weak")
    field(
        "bounds", f"every scan and the optimizer's code run in the OpenShell sandbox '{config['sandbox']}'; fixed gates"
    )

    section(2, "the starting point, measured before the demo")
    field("seed", describe(reference, rules))
    for label, count in label_counts(reference.digests).items():
        field("failure", f"{LABELS.get(label, label)}" + (f" ({count} pairs)" if count > 1 else ""))

    section(3, f"one turn of the optimizer, live (at most {config['proposer']['max_steps']} tool calls)")
    clock.lap()
    exp.run()

    outcome = exp.outcomes[-1] if exp.outcomes else None
    if outcome is None or outcome.score is None:
        print(paint("    no candidate was measured", "red"))
    else:
        lines = textwrap.wrap(" ".join(outcome.rationale.split()), width=96) or [""]
        field("why", lines[0])
        for line in lines[1:5]:
            print(f"{'':15}{line}")
        files, added = _diff_summary(outcome.diff)
        field("changed", ", ".join(files) or "nothing")
        for line in added:
            print(paint(f"             + {_short(line, 90)}", "dim"))
        field("measured", describe(outcome.score, rules, reference))
        if outcome.gates:
            field("verdict", paint("gated: " + "; ".join(outcome.gates), "red"))
        else:
            field("verdict", paint("cleared every gate", "green") + _rank(exp, outcome, reference))
    print(paint(f"    (measurement took {clock.lap()})", "dim"))

    section(5, "a person approves, then it is deployed into the sandbox")
    sandbox = OpenShell(config["sandbox"])
    if outcome is not None and outcome.score is not None and not outcome.gates:
        candidate = Path(outcome.directory)
    else:
        candidate = FALLBACK
        print("    the candidate did not clear the gates; offering the agent our full loop run produced instead")
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

    section(6, "the deployed agent scans a repository it has never seen, inside the sandbox")
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
    run.set_defaults(handler=cmd_run)
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
