# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The `security-agent synthetic` commands.

  bench prepare
  bench run --candidate DIR [--split train|val|test | --pair ID ... | --instance ID ...] [--sandbox NAME]
  bench score --run-dir DIR
  loop run [--config loop.yaml] [--run-dir DIR] [--iterations N] [--gpu-hours H] [--smoke] [--sandbox NAME]
  loop status --run-dir DIR
  scan REPO (--candidate DIR | --sandbox NAME) [--out FILE]
  sandbox deploy --sandbox NAME --candidate DIR
  gym export [--split train|val|test] [--pairs N] [--out FILE]

`--sandbox NAME` runs every scan, and every piece of the optimizer's code, inside that OpenShell sandbox
(`security_agent.synthetic.sandbox`). Without it, the candidate's code runs on this host. `scan --sandbox NAME`
without `--candidate` scans with the agent deployed in the sandbox. `sandbox run-job` is what runs inside the sandbox.
`gym export` writes the chosen pairs as NeMo Gym rows (gym/).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from security_agent.synthetic.bench.adapters import load_benchmark
from security_agent.synthetic.bench.runner import run
from security_agent.synthetic.config import RUNS_DIR, load_yaml, resolve

BENCHMARK = "hvbench"
HEADLINE_KEYS = (
    "paired_localization_accuracy",
    "strict_paired_accuracy",
    "mutant_localization_recall",
    "baseline_mapped_localization_false_alarm_rate",
)


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _sandbox(name: str | None) -> Any:
    if not name:
        print("note: no --sandbox: the candidate's code runs on this host", file=sys.stderr)
        return None
    from security_agent.synthetic.sandbox import OpenShell

    return OpenShell(name)


def _selected_pairs(benchmark: Any, selection: list[str]) -> list[dict]:
    """The planted pairs whose vulnerable repository and safe twin were both scanned."""
    from security_agent.synthetic.bench.pairs import is_planted, load_pairs

    chosen = set(selection)
    return [
        p
        for p in load_pairs(benchmark).values()
        if is_planted(p) and p["mutant_instance_id"] in chosen and p["baseline_instance_id"] in chosen
    ]


def _score(benchmark: Any, run_dir: Path) -> int:
    """Score a run with the benchmark's own scorer, and report the metrics over the pairs it scanned."""
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    report = benchmark.score(
        run_dir / "predictions.jsonl", run_dir / "score.json", allow_missing=manifest.get("subset", False)
    )
    from security_agent.synthetic.bench.pairs import summarize_pairs

    wanted = {p["pair_id"] for p in _selected_pairs(benchmark, manifest["selection"])}
    summary = summarize_pairs(report["pair_results"], wanted)
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("pairs", *HEADLINE_KEYS)}, indent=1))
    print(f"(full report: {run_dir / 'score.json'}; summary: {run_dir / 'summary.json'})")
    return 0


# -- bench -----------------------------------------------------------------------------------------


def cmd_prepare(args: argparse.Namespace) -> int:
    """Materialize the benchmark."""
    benchmark = load_benchmark(args.benchmark)
    benchmark.prepare()
    print(f"{benchmark.name}: {len(benchmark.instances())} repositories ready ({benchmark.manifest_path})")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Scan the benchmark with a candidate and score it."""
    from security_agent.optimize.splits import pairs
    from security_agent.synthetic.agent import AgentScanner
    from security_agent.synthetic.task import split

    benchmark = load_benchmark(args.benchmark)
    benchmark.prepare()
    scanner: Any = AgentScanner(Path(args.candidate).resolve(), model_config=args.model_config)
    if sandbox := _sandbox(args.sandbox):
        from security_agent.synthetic.sandbox import SandboxScanner

        scanner = SandboxScanner(scanner, sandbox)
    pair_ids = list(args.pair or [])
    if args.split:
        pair_ids += pairs(args.split, split()).get(benchmark.name, [])
    instance_ids = list(args.instance or []) + (benchmark.pair_instances(pair_ids) if pair_ids else [])
    name = Path(scanner.describe()["candidate"]).name
    run_dir = Path(args.run_dir) if args.run_dir else RUNS_DIR / f"{name}-{args.split or 'all'}-{_stamp()}"
    summary = run(benchmark, scanner, run_dir, concurrency=args.concurrency, instance_ids=instance_ids or None)
    print(
        json.dumps(
            {
                "run_dir": str(summary.run_dir),
                "repositories": summary.selected,
                "scanned": summary.scanned,
                "complete": summary.complete,
                "incomplete": summary.incomplete,
                "findings": summary.export.findings,
                "seconds": summary.seconds,
            },
            indent=1,
        )
    )
    return 0 if args.no_score else _score(benchmark, run_dir)


def cmd_score(args: argparse.Namespace) -> int:
    """Score a run directory."""
    return _score(load_benchmark(args.benchmark), Path(args.run_dir))


# -- loop ------------------------------------------------------------------------------------------


def cmd_loop_run(args: argparse.Namespace) -> int:
    """Start or resume an experiment of the self-improvement loop."""
    from security_agent.optimize.loop import Experiment
    from security_agent.optimize.proposer import agent_proposer
    from security_agent.optimize.runs import claim_run_dir
    from security_agent.optimize.splits import pairs, subsample
    from security_agent.synthetic.task import SyntheticTask, split

    given = Path(args.run_dir) if args.run_dir else None
    if given is not None and (given / "preregistration.json").is_file():
        # Resuming: the pre-registered configuration and training pairs win over the command line.
        data = json.loads((given / "preregistration.json").read_text(encoding="utf-8"))
        config, train, run_dir = data["config"], data["train"], given
    else:
        config = load_yaml(args.config)
        train = subsample(pairs("train", split()), int(config["train_per_benchmark"]), config["seed"])
        if args.iterations is not None:
            config["iterations"] = args.iterations
        if args.gpu_hours is not None:
            config["gpu_hours"] = args.gpu_hours
        if args.smoke:  # mechanics check: two training pairs, one candidate
            train = {name: sorted(ids)[:2] for name, ids in train.items()}
            config["iterations"] = args.iterations or 1
        runs = resolve(config.get("runs_dir", "runs/synthetic/loop"))
        run_dir = given or claim_run_dir(runs, "opt-smoke-" if args.smoke else "opt-")
    rules = config.get("rules", {})
    task = SyntheticTask(
        model_config=config.get("model_config") or "model.yaml",
        concurrency=int(config.get("concurrency", 8)),
        sandbox=_sandbox(args.sandbox),
        prefill_tps=float(rules.get("prefill_tps", 3000)),
        decode_tps=float(rules.get("decode_tps", 110)),
        log=lambda m: print(m, flush=True),
    )
    proposer = agent_proposer(task.model, config["proposer"], task.system_prompt(task.prompt_values(config, train)))
    experiment = Experiment(
        run_dir,
        config=config,
        train=train,
        reference=resolve(config["reference"]),
        proposer=proposer,
        task=task,
        log=lambda m: print(m, flush=True),
    )
    decision = experiment.run()
    print(json.dumps({k: decision[k] for k in ("stop_reason", "best", "best_directory")}, indent=1))
    print(
        "Next: pick among the candidates on the validation pairs (bench run --split val --candidate <directory>), "
        "then look at the test pairs once with the one you picked."
    )
    return 0


def cmd_loop_status(args: argparse.Namespace) -> int:
    """Summarize an experiment's journal."""
    from security_agent.optimize.runs import status_lines

    for line in status_lines(Path(args.run_dir)):
        print(line)
    return 0


# -- scan and deploy --------------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan one repository."""
    from security_agent.synthetic.agent import AgentScanner
    from security_agent.synthetic.staging import stage

    if not args.candidate and not args.sandbox:
        raise ValueError("give --candidate, --sandbox (the deployed agent), or both")
    sandbox = _sandbox(args.sandbox)
    model = load_yaml(args.model_config)
    staged = stage(Path(args.repo))
    try:
        if args.candidate:
            scanner: Any = AgentScanner(Path(args.candidate).resolve(), model_config=model)
            if sandbox:
                from security_agent.synthetic.sandbox import SandboxScanner

                scanner = SandboxScanner(scanner, sandbox)
            result = scanner.scan(staged)
        else:
            result = sandbox.scan_deployed(staged, model)
    finally:
        staged.cleanup()
    out = Path(args.out) if args.out else RUNS_DIR / f"scan-{Path(args.repo).resolve().name}-{_stamp()}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(result.model_dump_json(indent=1), encoding="utf-8")
    for f in result.findings:
        print(f"{f.path}:{f.line_start}-{f.line_end}  {f.cwe}  {f.title}")
    status = "" if result.complete else f" (incomplete: {result.error})"
    print(f"{len(result.findings)} findings{status}; full result: {out}")
    return 0 if result.complete else 1


def cmd_deploy(args: argparse.Namespace) -> int:
    """Approve a candidate and install it in the sandbox."""
    from security_agent.optimize.candidate import candidate_id, files
    from security_agent.synthetic.agent import check_candidate
    from security_agent.synthetic.sandbox import OpenShell

    directory = Path(args.candidate).resolve()
    if problems := check_candidate(directory):
        raise ValueError("the candidate breaks the contract: " + "; ".join(problems))
    sandbox = OpenShell(args.sandbox)
    if problems := sandbox.contract_test(directory):
        raise ValueError("the candidate fails the contract test: " + "; ".join(problems))
    cid = candidate_id(directory)
    print(f"candidate {directory} ({cid}): {', '.join(files(directory))}")
    question = f"Deploy it into the sandbox '{args.sandbox}'? Type 'yes' to approve: "
    if not args.yes and input(question).strip() != "yes":
        print("not deployed")
        return 1
    sandbox.deploy(
        directory,
        {
            "candidate_id": cid,
            "source": str(directory),
            "approved_by": args.approved_by,
            "approved_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        },
    )
    print(f"deployed {cid}; scan with: security-agent synthetic scan --sandbox {args.sandbox} <repository>")
    return 0


def cmd_gym_export(args: argparse.Namespace) -> int:
    """Write the chosen pairs as NeMo Gym rows."""
    from security_agent.synthetic.config import REPO_ROOT
    from security_agent.synthetic.gym import export

    out = (
        Path(args.out)
        if args.out
        else REPO_ROOT / "work" / "gym" / "synthetic" / f"{args.split}-{args.pairs or 'all'}.jsonl"
    )
    count = export(args.split, out, args.pairs)
    print(f"{count} rows -> {out}")
    return 0


def cmd_run_job(args: argparse.Namespace) -> int:
    """Inside the sandbox: run one uploaded job."""
    from security_agent.synthetic.sandbox import run_job

    run_job(Path(args.job), Path(args.out))
    return 0


def add_commands(parser: argparse.ArgumentParser) -> None:  # noqa: PLR0915 - one statement per option
    """The `synthetic` command group."""
    sub = parser.add_subparsers(dest="command", required=True)

    bench = sub.add_parser("bench", help="scan the benchmark with a candidate and score it")
    bench_sub = bench.add_subparsers(dest="bench_command", required=True)
    prepare = bench_sub.add_parser("prepare", help="materialize the benchmark's repositories into work/synthetic/")
    prepare.add_argument("--benchmark", default=BENCHMARK)
    prepare.set_defaults(handler=cmd_prepare)

    run_parser = bench_sub.add_parser("run", help="scan, export the predictions and score them")
    run_parser.add_argument(
        "--candidate", required=True, help="candidate directory (with pipeline.yaml), e.g. agents/synthetic/seed"
    )
    run_parser.add_argument("--benchmark", default=BENCHMARK)
    select = run_parser.add_mutually_exclusive_group()
    select.add_argument("--split", choices=("train", "val", "test"), help="scan the pairs of this role in the split")
    select.add_argument("--pair", action="append", help="scan the repositories of this pair (repeatable)")
    select.add_argument("--instance", action="append", help="scan this repository (repeatable)")
    run_parser.add_argument(
        "--run-dir", help="default: runs/synthetic/<candidate>-<split>-<time>; an existing one is resumed"
    )
    run_parser.add_argument("--concurrency", type=int, default=8, help="repositories scanned in parallel")
    run_parser.add_argument("--model-config", default="model.yaml", help="a file in the package's config/, or a path")
    run_parser.add_argument("--sandbox", help="run every scan inside this OpenShell sandbox")
    run_parser.add_argument("--no-score", action="store_true")
    run_parser.set_defaults(handler=cmd_run)

    score = bench_sub.add_parser("score", help="score a run directory with the benchmark's own scorer")
    score.add_argument("--run-dir", required=True)
    score.add_argument("--benchmark", default=BENCHMARK)
    score.set_defaults(handler=cmd_score)

    loop = sub.add_parser("loop", help="the self-improvement loop")
    loop_sub = loop.add_subparsers(dest="loop_command", required=True)
    loop_run = loop_sub.add_parser("run", help="start or resume an experiment")
    loop_run.add_argument("--config", default="loop.yaml", help="a file in the package's config/, or a path")
    loop_run.add_argument("--run-dir", help="experiment directory; an existing one is resumed as pre-registered")
    loop_run.add_argument("--iterations", type=int)
    loop_run.add_argument("--gpu-hours", type=float)
    loop_run.add_argument("--smoke", action="store_true", help="two training pairs, one candidate")
    loop_run.add_argument(
        "--sandbox", help="run every scan and all of the optimizer's code inside this OpenShell sandbox"
    )
    loop_run.set_defaults(handler=cmd_loop_run)
    loop_status = loop_sub.add_parser("status", help="summarize an experiment's journal")
    loop_status.add_argument("--run-dir", required=True)
    loop_status.set_defaults(handler=cmd_loop_status)

    scan = sub.add_parser("scan", help="scan one repository with a candidate, or with the agent deployed in a sandbox")
    scan.add_argument("repo", help="the repository directory")
    scan.add_argument("--candidate", help="candidate directory; without it, the agent deployed in --sandbox")
    scan.add_argument("--sandbox", help="run the scan inside this OpenShell sandbox")
    scan.add_argument("--model-config", default="model.yaml", help="a file in the package's config/, or a path")
    scan.add_argument("--out", help="where the full result goes (default: runs/synthetic/scan-<repo>-<time>.json)")
    scan.set_defaults(handler=cmd_scan)

    sandbox = sub.add_parser("sandbox", help="the OpenShell sandbox")
    sandbox_sub = sandbox.add_subparsers(dest="sandbox_command", required=True)
    deploy = sandbox_sub.add_parser("deploy", help="approve a candidate and install it in the sandbox")
    deploy.add_argument("--sandbox", required=True)
    deploy.add_argument("--candidate", required=True)
    deploy.add_argument("--approved-by", default="", help="who approved it, for the record")
    deploy.add_argument("--yes", action="store_true", help="approve without asking")
    deploy.set_defaults(handler=cmd_deploy)
    job = sandbox_sub.add_parser("run-job", help="inside the sandbox: run one uploaded job and write its result")
    job.add_argument("--job", required=True, help="the uploaded job directory; it is removed")
    job.add_argument("--out", required=True, help="where the result goes, as JSON")
    job.set_defaults(handler=cmd_run_job)

    gym = sub.add_parser("gym", help="the NeMo Gym environment (gym/)")
    gym_sub = gym.add_subparsers(dest="gym_command", required=True)
    gym_export = gym_sub.add_parser("export", help="write the chosen pairs as Gym rows, for `gym eval run --input`")
    gym_export.add_argument("--split", choices=("train", "val", "test"), default="test")
    gym_export.add_argument("--pairs", type=int, help="the first N pairs of the split, in its order (default: all)")
    gym_export.add_argument("--out", help="default: work/gym/synthetic/<split>-<pairs>.jsonl")
    gym_export.set_defaults(handler=cmd_gym_export)


def errors() -> tuple[type[Exception], ...]:
    """The errors the command line reports as a message, not a traceback."""
    from security_agent.synthetic.bench.adapters import BenchmarkError
    from security_agent.synthetic.bench.runner import RunError
    from security_agent.synthetic.sandbox import SandboxError

    return (BenchmarkError, RunError, SandboxError)
