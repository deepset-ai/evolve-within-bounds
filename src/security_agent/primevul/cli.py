# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The `security-agent primevul` commands.

  kb build [--qdrant-url URL]
  kb query TEXT [--agent DIR] [--top-k N]
  run --agent DIR [--split train|val|test] [--pairs N] [--concurrency N] [--thinking-budget N] [--run-dir DIR]
      [--sandbox NAME]
  loop run [--config loop.yaml] [--run-dir DIR] [--iterations N] [--gpu-hours H] [--smoke] [--sandbox NAME]
  loop status --run-dir DIR
  gym export [--split train|val|test] [--pairs N] [--out FILE]

`run` judges every function of the chosen pairs and prints aggregates only: paired accuracy, its factors, false
positive rates and a budget summary. Its run directory keeps every task's record (`tasks.json`, which makes the run
resumable), the summary (`summary.json`) and one label per pair (`pairs.jsonl`). The test split is PrimeVul's paired
test split (`holdout` in the benchmark file). `loop run` is the prompt loop (`security_agent.primevul.task` on the
shared loop, `security_agent.optimize`). `gym export` writes the chosen pairs as NeMo Gym rows (gym/).

`--sandbox NAME` judges every function inside that OpenShell sandbox (`security_agent.primevul.sandbox`), after checking
that the agent reaches the model and the knowledge base from there. Without it, the agent runs in this process.
`sandbox run-job` is what runs inside the sandbox.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from security_agent.primevul.agent import THINKING_BUDGET
from security_agent.primevul.tasks import DATA_FILE, REPO_ROOT

RUNS_DIR = REPO_ROOT / "runs" / "primevul"
CONFIG_DIR = Path(__file__).resolve().parent / "config"
SEED = REPO_ROOT / "agents" / "primevul" / "seed"
FILE_SPLIT = {"train": "train", "val": "val", "test": "holdout"}
USAGE_KEYS = ("tool_calls", "failed_tool_calls", "tasks_at_step_cap", "forced_final_answers", "errors")


def _kb_tool_parameters(agent_dir: Path) -> dict[str, Any]:
    """The init parameters of the `SecurityKbSearch` tool in an agent file."""
    from security_agent.primevul.agent import load_config

    for tool in load_config(agent_dir)["init_parameters"].get("tools") or []:
        component = (tool.get("data") or {}).get("component") or {}
        if component.get("type", "").endswith("SecurityKbSearch"):
            return dict(component.get("init_parameters") or {})
    raise ValueError(f"{agent_dir} has no search_security_kb tool")


def _sandbox(name: str | None, config: dict[str, Any]) -> Any:
    """The sandbox to judge in, once it reached the model and the knowledge base with `config`; None without a name."""
    if not name:
        return None
    from security_agent.primevul.sandbox import OpenShell

    sandbox = OpenShell(name)
    found = sandbox.check(config)
    reached = "the model and the knowledge base" if "documents" in found else "the model"
    print(f"sandbox {name}: the agent reaches {reached}", flush=True)
    return sandbox


def cmd_kb_build(args: argparse.Namespace) -> int:
    """Build the knowledge base into a fresh collection."""
    from security_agent.knowledge_base.build import build
    from security_agent.knowledge_base.settings import Settings

    stats = build(Settings.from_env(qdrant_url=args.qdrant_url))
    print(json.dumps({k: stats[k] for k in ("indexed", "counts", "total", "cert_c_commit", "seconds")}, indent=1))
    return 0


def cmd_kb_query(args: argparse.Namespace) -> int:
    """Retrieve for one query, as the agent's tool does before its sub-agent reads the results; no LLM."""
    from security_agent.knowledge_base.render import render_listing
    from security_agent.knowledge_base.search import SecurityKbSearch

    tool = SecurityKbSearch(**_kb_tool_parameters(Path(args.agent)))
    print(render_listing(tool.retrieve(args.text, top_k=args.top_k), query=args.text))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Judge every function of the chosen pairs with an agent, and score the pairs."""
    from security_agent.primevul import agent as agents
    from security_agent.primevul.measure import measure, tool_usage
    from security_agent.primevul.scoring import headline
    from security_agent.primevul.tasks import load_tasks, pair_up

    agent_path = Path(args.agent)
    config = agents.load_config(agent_path)
    budget = args.thinking_budget or None
    tasks = load_tasks(Path(args.data), FILE_SPLIT[args.split], args.pairs)
    name = agent_path.name if agent_path.is_dir() else agent_path.stem
    run_dir = Path(args.run_dir) if args.run_dir else RUNS_DIR / f"{name}-{args.split}-{args.pairs or 'all'}"
    sandbox = _sandbox(args.sandbox, agents.with_thinking_budget(config, budget))
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"{args.split}: {len(pair_up(tasks))} pairs, {len(tasks)} functions -> {run_dir}", flush=True)
    started = time.monotonic()
    metrics, records = measure(
        agents.with_thinking_budget(config, budget),
        tasks,
        concurrency=args.concurrency,
        log=lambda line: print(line, flush=True),
        cache=run_dir / "tasks.json",
        load_agent=agents.load_agent,
        sandbox=sandbox,
    )
    usage = tool_usage(records, config)
    summary = {
        "agent": str(agent_path),
        "configuration_id": agents.configuration_id(config),
        "split": args.split,
        "pairs": args.pairs,
        "thinking_budget": budget,
        "sandbox": args.sandbox,
        "metrics": metrics.to_dict(with_pairs=False),
        "usage": usage,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=1, default=str) + "\n", encoding="utf-8")
    with (run_dir / "pairs.jsonl").open("w", encoding="utf-8") as handle:
        for pair in metrics.pairs:
            handle.write(json.dumps({"pair_id": pair.pair_id, "label": pair.label}) + "\n")
    print(f"{name}: {headline(metrics)}  ({time.monotonic() - started:.0f}s this session)")
    print(f"{name} budget: {json.dumps({k: usage[k] for k in USAGE_KEYS})}")
    missing = sum(t.id not in records for t in tasks)
    if missing:
        print(f"{missing} functions were not judged because the sandbox failed: run the same command again")
        return 1
    return 0


def _resolve(path: str) -> Path:
    """A path from a config file: absolute, or relative to the repository checkout."""
    candidate = Path(path).expanduser()
    return candidate if candidate.is_absolute() else REPO_ROOT / candidate


def cmd_loop_run(args: argparse.Namespace) -> int:
    """Start or resume an experiment of the prompt loop."""
    import yaml

    from security_agent.optimize.loop import Experiment
    from security_agent.optimize.proposer import agent_proposer
    from security_agent.optimize.runs import claim_run_dir
    from security_agent.primevul import agent as agents
    from security_agent.primevul.task import BENCHMARK, PrimeVulTask
    from security_agent.primevul.tasks import load_tasks, pair_up

    run_dir = Path(args.run_dir) if args.run_dir else None
    if run_dir is not None and (run_dir / "preregistration.json").is_file():
        # Resuming: the pre-registered configuration and training pairs win over the command line.
        data = json.loads((run_dir / "preregistration.json").read_text(encoding="utf-8"))
        config, train = data["config"], data["train"]
    else:
        path = Path(args.config)
        path = path if path.parent != Path() or path.is_absolute() else CONFIG_DIR / path
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
        pairs = sorted(pair_up(load_tasks(Path(args.data), "train", int(config["train_pairs"]))))
        train = {BENCHMARK: pairs}
        if args.iterations is not None:
            config["iterations"] = args.iterations
        if args.gpu_hours is not None:
            config["gpu_hours"] = args.gpu_hours
        if args.smoke:  # mechanics check: two training pairs, one candidate
            train = {BENCHMARK: pairs[:2]}
            config["iterations"] = args.iterations or 1
    reference = _resolve(config["reference"])
    budget = config.get("thinking_budget")
    sandbox = _sandbox(args.sandbox, agents.with_thinking_budget(agents.load_config(reference), budget))
    if run_dir is None:
        runs = _resolve(config.get("runs_dir", "runs/primevul/loop"))
        run_dir = claim_run_dir(runs, "opt-smoke-" if args.smoke else "opt-")
    task = PrimeVulTask(
        reference,
        data=Path(args.data),
        concurrency=int(config.get("concurrency", 4)),
        thinking_budget=budget,
        sandbox=sandbox,
        log=lambda m: print(m, flush=True),
    )
    proposer = agent_proposer(
        config["model"], config["proposer"], task.system_prompt(task.prompt_values(config, train))
    )
    experiment = Experiment(
        run_dir,
        config=config,
        train=train,
        reference=reference,
        proposer=proposer,
        task=task,
        log=lambda m: print(m, flush=True),
    )
    decision = experiment.run()
    print(json.dumps({k: decision[k] for k in ("stop_reason", "best", "best_directory")}, indent=1))
    print(
        "Next: pick among the candidates on the validation pairs (run --split val --agent <directory>), then look at "
        "the test pairs once with the one you picked."
    )
    return 0


def cmd_loop_status(args: argparse.Namespace) -> int:
    """Summarize an experiment's journal."""
    from security_agent.optimize.runs import status_lines

    for line in status_lines(Path(args.run_dir)):
        print(line)
    return 0


def cmd_gym_export(args: argparse.Namespace) -> int:
    """Write the chosen pairs as NeMo Gym rows."""
    from security_agent.primevul.gym import export

    out = (
        Path(args.out)
        if args.out
        else REPO_ROOT / "work" / "gym" / "primevul" / f"{args.split}-{args.pairs or 'all'}.jsonl"
    )
    count = export(Path(args.data), FILE_SPLIT[args.split], out, args.pairs)
    print(f"{count} rows -> {out}")
    return 0


def cmd_run_job(args: argparse.Namespace) -> int:
    """Inside the sandbox: run one uploaded job."""
    from security_agent.primevul.sandbox import run_job

    run_job(Path(args.job), Path(args.out))
    return 0


def add_commands(parser: argparse.ArgumentParser) -> None:  # noqa: PLR0915 - one statement per option
    """The `primevul` command group."""
    sub = parser.add_subparsers(dest="command", required=True)

    kb = sub.add_parser("kb", help="the knowledge base behind the agents' search_security_kb tool")
    kb_sub = kb.add_subparsers(dest="kb_command", required=True)
    build = kb_sub.add_parser("build", help="read the CWE reference and the CERT C rules into a fresh collection")
    build.add_argument("--qdrant-url", help="default: http://localhost:6333, or KB_QDRANT_URL")
    build.set_defaults(handler=cmd_kb_build)
    query = kb_sub.add_parser("query", help="retrieve for one query with an agent's tool settings, without an LLM")
    query.add_argument("text")
    query.add_argument("--agent", default=str(SEED), help="whose tool settings to use (default: the seed)")
    query.add_argument("--top-k", type=int, default=5)
    query.set_defaults(handler=cmd_kb_query)

    run = sub.add_parser("run", help="judge the functions of the chosen pairs with an agent, and score the pairs")
    run.add_argument(
        "--agent", required=True, help="agent directory (with agent.yaml) or file, e.g. agents/primevul/seed"
    )
    run.add_argument("--split", choices=tuple(FILE_SPLIT), default="test")
    run.add_argument("--pairs", type=int, help="the first N pairs of the split, in file order (default: all)")
    run.add_argument("--data", default=str(DATA_FILE), help="the benchmark file")
    run.add_argument("--concurrency", type=int, default=4, help="functions judged in parallel")
    run.add_argument(
        "--thinking-budget",
        type=int,
        default=THINKING_BUDGET,
        help=f"reasoning tokens per reply, sent with each request; 0 sends none (default: {THINKING_BUDGET}, as the "
        "results ran)",
    )
    run.add_argument("--run-dir", help="default: runs/primevul/<agent>-<split>-<pairs>; an existing one is resumed")
    run.add_argument("--sandbox", help="judge every function inside this OpenShell sandbox")
    run.set_defaults(handler=cmd_run)

    loop = sub.add_parser("loop", help="the prompt loop")
    loop_sub = loop.add_subparsers(dest="loop_command", required=True)
    loop_run = loop_sub.add_parser("run", help="start or resume an experiment")
    loop_run.add_argument("--config", default="loop.yaml", help="a file in the package's config/, or a path")
    loop_run.add_argument("--data", default=str(DATA_FILE), help="the benchmark file")
    loop_run.add_argument("--run-dir", help="experiment directory; an existing one is resumed as pre-registered")
    loop_run.add_argument("--iterations", type=int)
    loop_run.add_argument("--gpu-hours", type=float)
    loop_run.add_argument("--smoke", action="store_true", help="two training pairs, one candidate")
    loop_run.add_argument("--sandbox", help="judge every function inside this OpenShell sandbox")
    loop_run.set_defaults(handler=cmd_loop_run)
    loop_status = loop_sub.add_parser("status", help="summarize an experiment's journal")
    loop_status.add_argument("--run-dir", required=True)
    loop_status.set_defaults(handler=cmd_loop_status)

    gym = sub.add_parser("gym", help="the NeMo Gym environment (gym/)")
    gym_sub = gym.add_subparsers(dest="gym_command", required=True)
    gym_export = gym_sub.add_parser("export", help="write the chosen pairs as Gym rows, for `gym eval run --input`")
    gym_export.add_argument("--split", choices=tuple(FILE_SPLIT), default="test")
    gym_export.add_argument("--pairs", type=int, help="the first N pairs of the split, in file order (default: all)")
    gym_export.add_argument("--data", default=str(DATA_FILE), help="the benchmark file")
    gym_export.add_argument("--out", help="default: work/gym/primevul/<split>-<pairs>.jsonl")
    gym_export.set_defaults(handler=cmd_gym_export)

    sandbox = sub.add_parser("sandbox", help="the OpenShell sandbox")
    sandbox_sub = sandbox.add_subparsers(dest="sandbox_command", required=True)
    job = sandbox_sub.add_parser("run-job", help="inside the sandbox: run one uploaded job and write its result")
    job.add_argument("--job", required=True, help="the uploaded job directory; it is removed")
    job.add_argument("--out", required=True, help="where the result goes, as JSON")
    job.set_defaults(handler=cmd_run_job)


def errors() -> tuple[type[Exception], ...]:
    """The errors the command line reports as a message, not a traceback."""
    from security_agent.knowledge_base.store import KbStoreError
    from security_agent.sandbox import SandboxError

    return (KbStoreError, FileNotFoundError, SandboxError)
