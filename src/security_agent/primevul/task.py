# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
PrimeVul as a task for the shared loop (`security_agent.optimize`): the prompt loop.

- **Candidates** are directories with one file, `agent.yaml`. The optimizer may change the agent's system prompt, the
  tool's description, its step budget, its output limit and its timeout; the contract (`check_candidate`) holds the
  rest fixed: the model and endpoint, the temperature, the tool and its settings, and the JSON verdict.
- **Measuring** judges both functions of every pair (`security_agent.primevul.measure`), half by half. A pair is right
  when its label is `correct`; strictly right when the CWE on the vulnerable function is right too. A finding is a
  function called vulnerable, so among candidates with as many pairs right, fewer false alarms rank higher. GPU time
  is estimated from the tokens of the agent and of its knowledge-base sub-agent.
- **Digests** show up to `MAX_DIGESTS` failing pairs, spread over the failure labels: both verdicts, the patch between
  the two functions (what the agent never sees side by side) and what the agent did on each.
- **Leakage** is code copied from a training function, or a function name that identifies one training pair.
- **The optimizer's prompt** is `prompts/optimizer.md`, with the experiment's numbers filled in.
"""

from __future__ import annotations

import difflib
import json
import re
from collections.abc import Callable
from pathlib import Path
from string import Template
from typing import Any

from security_agent.optimize.measurement import Measurement
from security_agent.primevul import agent as agents
from security_agent.primevul.measure import measure
from security_agent.primevul.scoring import PairResult, aggregate, label
from security_agent.primevul.tasks import DATA_FILE, Task, load_tasks, pair_up
from security_agent.primevul.verdict import normalize_cwe

BENCHMARK = "primevul"
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"
MAX_DIGESTS = 12
MAX_DIFF_LINES = 60
MAX_RATIONALE_CHARS = 500
MAX_STEPS_SHOWN = 10
MAX_CODE_LINES = 150
MAX_READS = 8
VERDICT_KEYS = ("is_vulnerable", "cwe", "vulnerable_lines", "rationale")
FAILURE_LABELS = ("missed_fix", "missed_bug", "inverted", "parse_error")

# Names that say nothing about which pair was seen: libc, kernel helpers, words a reviewing prompt uses anyway.
GENERIC_IDENTIFIERS = frozenset(
    [
        "return",
        "sizeof",
        "static",
        "memcpy",
        "memmove",
        "memset",
        "memcmp",
        "strlen",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "strcmp",
        "strncmp",
        "strchr",
        "strrchr",
        "strstr",
        "strdup",
        "strtol",
        "strtoul",
        "strtoll",
        "atoi",
        "snprintf",
        "sprintf",
        "printf",
        "fprintf",
        "vsnprintf",
        "malloc",
        "calloc",
        "realloc",
        "free",
        "alloca",
        "assert",
        "define",
        "include",
        "struct",
        "unsigned",
        "signed",
        "typedef",
        "inline",
        "extern",
        "volatile",
        "register",
        "string",
        "memory",
        "buffer",
        "length",
        "offset",
        "object",
        "pointer",
        "handle",
        "context",
        "result",
        "status",
        "count",
        "index",
        "value",
        "values",
        "data",
        "bytes",
        "size_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "int32_t",
        "int64_t",
        "kmalloc",
        "kfree",
        "kzalloc",
        "krealloc",
        "vmalloc",
        "vfree",
        "spin_lock",
        "spin_unlock",
        "mutex_lock",
        "mutex_unlock",
        "list_for_each",
        "container_of",
        "likely",
        "unlikely",
        "min",
        "max",
        "abs",
        "lookup",
        "search",
        "parse",
        "check",
        "verify",
        "read",
        "write",
        "update",
        "insert",
        "remove",
        "delete",
        "append",
        "process",
        "handler",
        "callback",
        "compare",
        "validate",
        "encode",
        "decode",
        "format",
        "convert",
        "create",
        "destroy",
        "init",
        "cleanup",
        "release",
        "acquire",
    ]
)
_CALLED = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{5,})\s*\(")

TOOL_SPECS: dict[str, dict[str, Any]] = {
    "read_reasoning": {
        "description": (
            "Read what the agent did on one function of a training pair in the draft's latest measurement: the "
            "function with line numbers, the agent's verdict, its tool calls with the head of each result (and what "
            "the knowledge-base sub-agent did), its steps and time, and the head of its answer. Use it on pairs that "
            f"stand for the pattern you want to change. At most {MAX_READS} reads per turn; costs no GPU."
        ),
        "parameters": {
            "example": {"type": "string", "description": "A training pair key, e.g. 'primevul/<pair id>'."},
            "side": {
                "type": "string",
                "enum": ["vulnerable", "fixed"],
                "description": "The vulnerable function or its patched twin (default vulnerable).",
            },
            "run": {"type": "integer", "description": "Always 1: one run per measurement."},
        },
        "required": ["example"],
    }
}


def _squashed(code: str) -> str:
    return " ".join(code.split())


def pair_names(pairs: dict[str, dict[str, Task]]) -> list[str]:
    """
    Function names that identify one pair: called or defined in one pair's code only, and not generic.

    A plain lowercase word ("complete", "single") is English before it is a function name; a real leak carries an
    underscore, a digit or mixed case.
    """
    owners: dict[str, set[str]] = {}
    for pid, members in pairs.items():
        for task in members.values():
            for name in set(_CALLED.findall(task.gold.get("code", ""))):
                owners.setdefault(name, set()).add(pid)
    return sorted(
        name
        for name, pids in owners.items()
        if len(pids) == 1 and name.lower() not in GENERIC_IDENTIFIERS and not re.fullmatch(r"[a-z]+", name)
    )


def check_candidate(directory: Path, reference: dict[str, Any]) -> list[str]:
    """Problems with a candidate: its files, whether it loads, and what must stay as in `reference`."""
    files = sorted(p.relative_to(directory).as_posix() for p in Path(directory).rglob("*") if p.is_file())
    if files != ["agent.yaml"]:
        return [f"a candidate is one file, agent.yaml; found {files}"]
    try:
        config = agents.load_config(Path(directory))
        agents.load_agent(config)
    except Exception as exc:
        return [f"agent.yaml does not load as a Haystack Agent: {type(exc).__name__}: {exc}"[:600]]
    problems = []
    gen, ref_gen = (c["init_parameters"]["chat_generator"]["init_parameters"] for c in (config, reference))
    if config["init_parameters"]["chat_generator"]["type"] != reference["init_parameters"]["chat_generator"]["type"]:
        problems.append("the chat generator's type must stay as it is")
    for key in ("model", "api_base_url", "api_key"):
        if gen.get(key) != ref_gen.get(key):
            problems.append(f"chat_generator.{key} must stay {ref_gen.get(key)!r}")
    kwargs, ref_kwargs = gen.get("generation_kwargs") or {}, ref_gen.get("generation_kwargs") or {}
    for key in set(kwargs) | set(ref_kwargs):
        if key != "max_tokens" and kwargs.get(key) != ref_kwargs.get(key):
            problems.append(f"generation_kwargs.{key} must stay {ref_kwargs.get(key)!r}; only max_tokens may change")
    tools, ref_tools = config["init_parameters"].get("tools") or [], reference["init_parameters"].get("tools") or []
    if len(tools) != len(ref_tools):
        problems.append("tools must not be added or removed")
    for tool, ref_tool in zip(tools, ref_tools, strict=False):
        if tool.get("type") != ref_tool.get("type") or tool["data"].get("name") != ref_tool["data"].get("name"):
            problems.append(f"tool {ref_tool['data'].get('name')!r} must keep its name and type")
        for key in ("component", "parameters", "outputs_to_string", "inputs_from_state", "outputs_to_state"):
            if tool["data"].get(key) != ref_tool["data"].get(key):
                problems.append(
                    f"tool {ref_tool['data'].get('name')!r}: {key} must stay as it is; only its description may change"
                )
    prompt = config["init_parameters"].get("system_prompt") or ""
    missing = [key for key in VERDICT_KEYS if key not in prompt]
    if missing:
        problems.append(
            f"the system prompt must still ask for the JSON verdict with {', '.join(VERDICT_KEYS)} "
            f"(missing: {', '.join(missing)})"
        )
    return problems


def patch_diff(vulnerable: str, fixed: str, max_lines: int = MAX_DIFF_LINES) -> str:
    """The unified diff from the vulnerable function to its patched twin, shortened."""
    lines = list(
        difflib.unified_diff(vulnerable.splitlines(), fixed.splitlines(), "vulnerable", "fixed", lineterm="", n=2)
    )
    if len(lines) > max_lines:
        lines = [*lines[:max_lines], f"... [{len(lines) - max_lines} more diff lines]"]
    return "\n".join(lines)


def _short(verdict: dict[str, Any] | None) -> dict[str, Any]:
    if not verdict:
        return {"verdict": "none"}
    if verdict.get("parse_error"):
        return {"verdict": "parse_error", "raw": (verdict.get("raw") or "")[:200]}
    return {
        "verdict": "vulnerable" if verdict.get("is_vulnerable") else "benign",
        "cwe": verdict.get("cwe"),
        "lines": (verdict.get("vulnerable_lines") or [])[:10],
        "rationale": (verdict.get("rationale") or "")[:MAX_RATIONALE_CHARS],
    }


def build_digests(results: list[PairResult], pairs: dict[str, dict[str, Task]], records: dict[str, dict]) -> list[dict]:
    """Up to `MAX_DIGESTS` failing pairs, taken in turn from each failure label so that none crowds out the rest."""
    by_label: dict[str, list[PairResult]] = {}
    for result in results:
        if result.label != "correct":
            by_label.setdefault(result.label, []).append(result)
    chosen: list[PairResult] = []
    while len(chosen) < MAX_DIGESTS and any(by_label.values()):
        for name in FAILURE_LABELS:
            if by_label.get(name) and len(chosen) < MAX_DIGESTS:
                chosen.append(by_label[name].pop(0))
    digests = []
    for result in chosen:
        members = pairs[result.pair_id]
        digest: dict[str, Any] = {
            "key": f"{BENCHMARK}/{result.pair_id}",
            "labels": [result.label],
            "gold_cwe": result.gold_cwe,
            "patch": patch_diff(members["vulnerable"].gold.get("code", ""), members["fixed"].gold.get("code", "")),
        }
        for slot, verdict in (("vulnerable", result.vulnerable_verdict), ("fixed", result.fixed_verdict)):
            record = records.get(members[slot].id) or {}
            digest[slot] = {
                **_short(verdict),
                "steps": record.get("steps"),
                "seconds": record.get("seconds"),
                "trajectory": record.get("trajectory") or [],
            }
        digests.append(digest)
    return digests


def _render_steps(steps: list[dict[str, Any]]) -> list[str]:
    lines = []
    for step in steps[:MAX_STEPS_SHOWN]:
        if "reply_chars" in step:
            lines.append(f"    reply ({step['reply_chars']} characters)")
            continue
        failed = " FAILED" if step.get("failed") else ""
        lines.append(f"    {step.get('tool')}({step.get('args', '')}){failed} -> {step.get('result', '')!r}")
        sub = step.get("sub_agent")
        if sub:
            calls = "; ".join(
                f"{c.get('tool')}({c.get('args', '')}){' FAILED' if c.get('failed') else ''}"
                for c in sub.get("calls", [])
            )
            lines.append(
                f"      sub-agent: {sub.get('documents')} documents, {sub.get('steps')} steps, {sub.get('seconds')} s"
                + (f", error {sub['error']}" if sub.get("error") else "")
                + (f"; calls: {calls}" if calls else "")
            )
    if len(steps) > MAX_STEPS_SHOWN:
        lines.append(f"    ... [{len(steps) - MAX_STEPS_SHOWN} more steps]")
    return lines


def render(digest: dict[str, Any]) -> str:
    """One failing pair for the optimizer: both verdicts, the patch, and what the agent did on each function."""
    lines = [f"### {digest['key']}: {digest['labels'][0]} (gold CWE {digest.get('gold_cwe') or 'unknown'})"]
    for slot, name in (("vulnerable", "Vulnerable function"), ("fixed", "Patched twin")):
        member = digest[slot]
        verdict = member["verdict"]
        if verdict in ("vulnerable", "benign"):
            verdict += f", CWE {member.get('cwe')}, lines {member.get('lines')}: {member.get('rationale')}"
        lines.append(f"- {name}: {verdict}  ({member.get('steps')} steps, {member.get('seconds')} s)")
        lines += _render_steps(member.get("trajectory") or [])
    lines += ["The patch:", "```diff", digest["patch"], "```"]
    return "\n".join(lines)


class ReasoningReader:
    """`read_reasoning`: one function's record from the best candidate's latest measurement, with its code."""

    def __init__(self, pairs: dict[str, dict[str, Task]], best: Callable[[], Measurement | None]) -> None:
        self.pairs = pairs
        self.best = best

    def __call__(self, example: str, side: str = "vulnerable", run: int = 1) -> str:  # noqa: ARG002 - one run
        """The record as text, or an error as JSON."""
        pair_id = example.split("/", 1)[-1]
        if pair_id not in self.pairs:
            return json.dumps({"ok": False, "error": f"'{example}' is not a training pair key"})
        if side not in ("vulnerable", "fixed"):
            return json.dumps({"ok": False, "error": "side must be 'vulnerable' or 'fixed'"})
        task = self.pairs[pair_id][side]
        measurement = self.best()
        record = None
        for run_dir in measurement.run_dirs if measurement else []:
            cache = Path(run_dir) / "tasks.json"
            if cache.is_file():
                record = {r["task_id"]: r for r in json.loads(cache.read_text(encoding="utf-8"))}.get(task.id)
        if record is None:
            return json.dumps(
                {"ok": False, "error": "this function was not measured in the draft's latest measurement"}
            )
        code = task.gold.get("code", "").splitlines()
        numbered = [f"{n:4d}  {line}" for n, line in enumerate(code[:MAX_CODE_LINES], 1)]
        if len(code) > MAX_CODE_LINES:
            numbered.append(f"... [{len(code) - MAX_CODE_LINES} more lines]")
        lines = [
            f"{example}, the {'patched twin' if side == 'fixed' else 'vulnerable function'}",
            "```c",
            *numbered,
            "```",
            f"Verdict: {json.dumps(_short(record.get('verdict')))}",
            f"Steps {record.get('steps')}, {record.get('seconds')} s"
            + (", forced final answer" if record.get("forced") else ""),
            *_render_steps(record.get("trajectory") or []),
            f"Answer: {(record.get('answer') or '')[:1500]!r}",
        ]
        if record.get("error"):
            lines.append(f"Error: {record['error']}")
        return "\n".join(lines)


class PrimeVulTask:
    """
    PrimeVul, as the loop sees it.

    :param reference: the starting agent's directory; the contract holds candidates to it.
    :param data: the benchmark file.
    :param concurrency: functions judged in parallel.
    :param thinking_budget: reasoning tokens per reply, sent with each request.
    :param load_agent: builds an agent from a config (tests pass a fake).
    :param sandbox: a `security_agent.primevul.sandbox.OpenShell`; every function is then judged inside it.
    """

    name = BENCHMARK
    unit = "function"

    def __init__(
        self,
        reference: Path,
        *,
        data: Path = DATA_FILE,
        concurrency: int = 4,
        thinking_budget: int | None = agents.THINKING_BUDGET,
        load_agent: Callable[[dict[str, Any]], Any] = agents.load_agent,
        sandbox: Any = None,
        log: Callable[[str], None] = print,
    ) -> None:
        self.reference = agents.load_config(Path(reference))
        self.tasks = load_tasks(Path(data), "train")
        self.pairs = pair_up(self.tasks)
        self.concurrency = concurrency
        self.thinking_budget = thinking_budget
        self.load_agent = load_agent
        self.sandbox = sandbox
        self.log = log

    def _tasks(self, pair_ids: list[str]) -> list[Task]:
        missing = [p for p in pair_ids if p not in self.pairs]
        if missing:
            raise ValueError(f"not training pairs of the benchmark file: {missing[:5]}")
        return [self.pairs[p][slot] for p in pair_ids for slot in ("vulnerable", "fixed")]

    def measure(
        self,
        candidate: Path,
        parts: list[dict[str, list[str]]],
        out_dir: Path,
        *,
        label: str,
        abort: Callable[[Measurement], bool] | None = None,
    ) -> Measurement:
        """Judge both functions of every pair, part by part; `abort` is checked between parts."""
        config = agents.with_thinking_budget(agents.load_config(candidate), self.thinking_budget)
        cache = out_dir / "tasks.json"
        m = Measurement(label=label, run_dirs=[str(out_dir)])
        measured: list[str] = []
        records: dict[str, dict] = {}
        for k, part in enumerate(parts, 1):
            pair_ids = part.get(BENCHMARK, [])
            if not pair_ids:
                continue
            self.log(f"  [{label}] part {k}: {len(pair_ids)} pairs, {2 * len(pair_ids)} functions")
            metrics, records = measure(
                config,
                self._tasks(pair_ids),
                concurrency=self.concurrency,
                cache=cache,
                load_agent=self.load_agent,
                sandbox=self.sandbox,
                log=lambda line: self.log(f"  [{label}]{line}"),
            )
            m.seconds += metrics.seconds
            measured += pair_ids
            self._fill(m, measured, records)
            self.log(f"  [{label}] after part {k}: {m.right}/{m.pairs} pairs right, {m.strict} with the right CWE")
            if abort is not None and k < len(parts) and abort(m):
                m.aborted = True
                break
        m.seconds = round(m.seconds, 1)
        pairs = {p: self.pairs[p] for p in measured}
        verdicts = {tid: r["verdict"] for tid, r in records.items()}
        m.digests = build_digests(aggregate(pairs, verdicts).pairs, pairs, records)
        return m

    def _fill(self, m: Measurement, pair_ids: list[str], records: dict[str, dict]) -> None:
        """
        Outcomes, instances, findings, cost and incomplete functions of the measured pairs.

        Incomplete: lost to a model-server outage, or not judged because the sandbox failed.
        """
        from security_agent.generator import server_error_text

        m.outcomes, m.instances, m.findings, m.incomplete = {}, 0, 0, 0
        m.cost = {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0, "cached_tokens": 0}
        pairs = {p: self.pairs[p] for p in pair_ids}
        verdicts = {tid: r["verdict"] for tid, r in records.items()}
        for result in aggregate(pairs, verdicts).pairs:
            right = result.label == "correct"
            cwe_right = right and normalize_cwe((result.vulnerable_verdict or {}).get("cwe")) == result.gold_cwe
            m.outcomes[f"{BENCHMARK}/{result.pair_id}"] = [cwe_right, right]
        for task in self._tasks(pair_ids):
            record = records.get(task.id) or {}
            m.instances += 1
            m.findings += label(record.get("verdict")) is True
            m.incomplete += task.id not in records or server_error_text(record.get("error"))
            for key, value in (record.get("usage") or {}).items():
                m.cost[key] = m.cost.get(key, 0) + int(value)

    def render(self, digest: dict[str, Any]) -> str:
        """One failure digest as text."""
        return render(digest)

    def shown_material(self, digests: list[dict[str, Any]]) -> dict[str, list[str]]:
        """The training functions behind the digests."""
        return self.training_material({BENCHMARK: [d["key"].split("/", 1)[1] for d in digests]})

    def training_material(self, train: dict[str, list[str]]) -> dict[str, list[str]]:
        """Every training function's code, and the function names that identify one training pair."""
        pairs = {p: self.pairs[p] for p in train.get(BENCHMARK, []) if p in self.pairs}
        code = [_squashed(t.gold.get("code", "")) for members in pairs.values() for t in members.values()]
        return {"code": code, "names": pair_names(pairs)}

    def scoring(self) -> str:
        """How a pair is scored."""
        return (
            "Each function is judged alone. A pair is right when the agent calls the vulnerable function vulnerable "
            "and its patched twin benign; strictly right when it also names the right CWE. A finding is a function "
            "called vulnerable."
        )

    def workspace_options(
        self,
        train: dict[str, list[str]],
        best: Callable[[], Measurement | None],
        on_shown: Callable[[dict[str, list[str]]], None],  # noqa: ARG002 - read_reasoning shows training code only
    ) -> dict[str, Any]:
        """The contract against the starting agent, and `read_reasoning`."""
        pairs = {p: self.pairs[p] for p in train.get(BENCHMARK, []) if p in self.pairs}
        return {
            "check": lambda draft: check_candidate(draft, self.reference),
            "reasoning_reader": ReasoningReader(pairs, best),
            "tool_specs": TOOL_SPECS,
            "max_reasoning_reads": MAX_READS,
        }

    def spoiled(self, measurement: Measurement) -> int:
        """
        Drop functions a model-server outage spoiled from the measurement's records; how many will run again.

        Those run again with the functions the sandbox failed to judge, which have no record.
        """
        from security_agent.generator import server_error_text

        judged: set[str] = set()
        for run_dir in measurement.run_dirs:
            cache = Path(run_dir) / "tasks.json"
            if not cache.is_file():
                continue
            records = json.loads(cache.read_text(encoding="utf-8"))
            kept = [r for r in records if not server_error_text(r.get("error"))]
            if len(kept) != len(records):
                cache.write_text(json.dumps(kept, default=str), encoding="utf-8")
            judged |= {r["task_id"] for r in kept}
        measured = [key.split("/", 1)[1] for key in measurement.outcomes]
        return sum(t.id not in judged for p in measured if p in self.pairs for t in self.pairs[p].values())

    def system_prompt(self, values: dict[str, Any]) -> str:
        """The optimizer's system prompt with the experiment's numbers filled in."""
        return Template((PROMPTS_DIR / "optimizer.md").read_text(encoding="utf-8")).substitute(**values)

    @staticmethod
    def prompt_values(config: dict[str, Any], train: dict[str, list[str]]) -> dict[str, Any]:
        """The experiment's numbers in the prompt."""
        rules = config["rules"]
        return {
            "train_pairs": sum(len(ids) for ids in train.values()),
            "budget_hours": config["gpu_hours"],
            "abort_behind": rules["abort_behind"],
            "max_gpu_minutes": rules["max_gpu_minutes_per_repo"],
            "max_reads": MAX_READS,
        }
