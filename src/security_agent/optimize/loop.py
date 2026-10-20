# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The self-improvement loop: an optimizer agent improves an agent, candidate by candidate, on training pairs.

The loop is the same for every benchmark; what depends on the benchmark comes from its task
(`security_agent.optimize.task`). One experiment, in its own run directory:

1. **Pre-registration.** The rules, the training pairs, the two training halves, the starting candidate and the budget
   go to `preregistration.json` before anything is measured.
2. **Starting candidate.** It is measured on the training pairs; its score is the bar.
3. **Turns.** Each turn resets the draft to the best candidate so far. The optimizer edits it and submits one
   candidate, which is measured on training half 1, then (unless aborted) half 2, and gated:
   - leakage (the candidate copies training answers);
   - more incomplete instances than the starting candidate;
   - more estimated GPU time, or more findings, per instance than the fixed limits;
   - early abort after half 1: too far behind the starting candidate there, or too expensive;
   - its own code failed on too many instances.

   An eligible candidate becomes the best only if it ranks strictly above it: more pairs right, then fewer findings,
   then less GPU time. The loop stops after `iterations` candidates, when the GPU budget is spent, when the optimizer
   calls `finish`, or after two turns in a row without a candidate.
4. **Decision.** `decision.json` names the best candidate on the training pairs and lists every candidate. Validation
   pairs never enter the loop: pick among the candidates on them afterwards, and look at the test pairs once at the end.

GPU time is estimated from tokens: prompt tokens not served from the server's prefix cache at its prefill speed, plus
output tokens at its decode speed (`prefill_tps`, `decode_tps`).

The journal (`journal.jsonl`) makes the experiment resumable: a restart skips finished work and measures again a
candidate whose measurement was interrupted. Instances spoiled by a model-server outage are measured again on resume,
at no cost to the budget.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_agent.optimize import candidate as cand
from security_agent.optimize.leakage import Leakage
from security_agent.optimize.measurement import Measurement
from security_agent.optimize.proposer import Proposer
from security_agent.optimize.task import Task
from security_agent.optimize.workspace import Workspace

DIFF_CHARS = 6_000  # a candidate's diff in the optimizer's context, at most


@dataclass(frozen=True)
class Rules:
    """The gates and the cost model. Per instance means per item the task measures, on average."""

    abort_behind: int = 4  # abort after half 1 when this many pairs behind the starting candidate there
    max_gpu_minutes_per_repo: float = 6.0  # estimated GPU minutes per instance
    max_findings_per_repo: float = 10.0  # findings per instance
    cost_abort_slack: float = 1.2  # abort after half 1 when its GPU time there is this much above the limit
    max_tool_error_rate: float = 0.05  # share of instances on which the candidate's own code may fail
    prefill_tps: float = 3000.0  # prompt tokens per second at full load
    decode_tps: float = 110.0  # output tokens per second at full load

    def text(self, scoring: str, unit: str) -> str:
        """The rules in words, for the pre-registration."""
        return (
            f"SCORING. {scoring} "
            f"GATES. A candidate is eligible only if (1) the text it adds has no leakage hits, (2) it has no more "
            f"incomplete instances than the starting candidate, (3) its estimated GPU time (prompt tokens not served "
            f"from the server's cache / {self.prefill_tps:g} plus output tokens / {self.decode_tps:g} seconds) is at "
            f"most {self.max_gpu_minutes_per_repo:g} minutes per {unit} on average, (4) it reports at most "
            f"{self.max_findings_per_repo:g} findings per {unit} on average, (5) it was not aborted early: after "
            f"training half 1 when it has {self.abort_behind} or more fewer pairs right than the starting candidate "
            f"there, or its GPU time there is above {self.max_gpu_minutes_per_repo * self.cost_abort_slack:g} minutes "
            f"per {unit}, and (6) its own code failed on at most {self.max_tool_error_rate:.0%} of the instances. "
            "Eligible candidates rank by pairs right, then fewer findings, then less GPU time; the best so far changes "
            "only on a strictly better rank."
        )


def mcnemar_one_sided(b: int, c: int) -> float:
    """P(X >= b) for X ~ Binomial(b + c, 1/2): the chance of at least b wins among b + c discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    return sum(math.comb(n, k) for k in range(b, n + 1)) / 2**n


def discordant(a: Measurement, b: Measurement) -> tuple[int, int]:
    """(pairs a gets right and b does not, the reverse), over their common pairs."""
    common = set(a.outcomes) & set(b.outcomes)
    return (
        sum(1 for k in common if a.outcomes[k][1] and not b.outcomes[k][1]),
        sum(1 for k in common if b.outcomes[k][1] and not a.outcomes[k][1]),
    )


def split_halves(train: dict[str, list[str]], seed: int) -> list[dict[str, list[str]]]:
    """The training pairs in two fixed halves, for the early abort."""
    first, second = {}, {}
    for name, ids in sorted(train.items()):
        shuffled = sorted(ids)
        random.Random(f"{seed}:{name}").shuffle(shuffled)
        cut = (len(shuffled) + 1) // 2
        first[name], second[name] = sorted(shuffled[:cut]), sorted(shuffled[cut:])
    return [first, second]


def keys(part: dict[str, list[str]]) -> list[str]:
    """The pair keys (`<benchmark>/<pair_id>`) of a set of pairs."""
    return [f"{name}/{p}" for name, ids in part.items() for p in ids]


def gpu_seconds(cost: Mapping[str, float], rules: Rules) -> float:
    """Estimated GPU time of token counts at the server's speeds. Cached prompt tokens are not computed again."""
    computed = cost["prompt_tokens"] - cost.get("cached_tokens", 0)
    return computed / rules.prefill_tps + cost["completion_tokens"] / rules.decode_tps


def rank_key(m: Measurement, rules: Rules) -> tuple:
    """Lower is better: more pairs right, then fewer findings, then less GPU time."""
    return (-m.right, m.findings, gpu_seconds(m.cost, rules))


def label_counts(digests: list[dict]) -> dict[str, int]:
    """How often each failure label occurs."""
    counts: dict[str, int] = {}
    for digest in digests:
        for label in digest["labels"]:
            counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def gate_failures(m: Measurement, reference: Measurement, rules: Rules, leakage: list[str], unit: str) -> list[str]:
    """Why a measured candidate is not eligible; empty when it is."""
    failures = [f"leakage: {hit}" for hit in leakage]
    if m.aborted:
        failures.append("early_abort" + (f": {m.abort_reason}" if m.abort_reason else ""))
    if m.incomplete > reference.incomplete:
        failures.append(f"incomplete: {m.incomplete} vs {reference.incomplete}")
    per = max(1, m.instances)
    if not m.aborted:
        minutes = gpu_seconds(m.cost, rules) / 60 / per
        if minutes > rules.max_gpu_minutes_per_repo:
            limit = rules.max_gpu_minutes_per_repo
            failures.append(f"cost: {minutes:.1f} GPU-minutes per {unit}, above the limit of {limit:g}")
        if m.findings / per > rules.max_findings_per_repo:
            limit = rules.max_findings_per_repo
            failures.append(f"findings: {m.findings / per:.1f} per {unit}, above the limit of {limit:g}")
    if m.tool_errors > rules.max_tool_error_rate * per:
        failures.append(f"tool_errors: the candidate's code failed on {m.tool_errors} of {m.instances} instances")
    return failures


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def code_hash() -> str:
    """A hash of this package's code and prompts, for the pre-registration."""
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.suffix in (".py", ".md") and "__pycache__" not in p.parts):
        digest.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()[:16]


def _fenced(text: str, lang: str = "") -> str:
    fence = "```"
    while fence in text:
        fence += "`"
    return f"{fence}{lang}\n{text}\n{fence}"


@dataclass
class Outcome:
    """One submitted candidate and what became of it."""

    turn: int
    candidate_id: str
    parent_id: str
    directory: str
    rationale: str
    diff: str
    auto: bool = False
    score: Measurement | None = None
    gates: list[str] | None = None
    failure: str | None = None

    @property
    def label(self) -> str:
        """`c<turn>-<id>`, the name of its directory and measurement."""
        return f"c{self.turn + 1:03d}-{self.candidate_id[:8]}"


class Experiment:
    """
    One run of the loop.

    :param run_dir: the experiment's directory; an existing one is resumed.
    :param config: `iterations`, `gpu_hours`, `seed`, `rules` and `min_reasoning_reads`; recorded as is.
    :param train: the training pairs, `{benchmark: [pair_id, ...]}`.
    :param reference: the starting candidate's directory.
    :param proposer: the optimizer (`security_agent.optimize.proposer.agent_proposer`).
    :param task: the benchmark (`security_agent.optimize.task.Task`).
    :param workspace_options: overrides the task's workspace options (tests).
    """

    def __init__(
        self,
        run_dir: Path,
        *,
        config: dict[str, Any],
        train: dict[str, list[str]],
        reference: Path,
        proposer: Proposer,
        task: Task,
        workspace_options: dict[str, Any] | None = None,
        log: Callable[[str], None] = print,
    ) -> None:
        self.run_dir = Path(run_dir)
        self.config = config
        self.train = train
        self.reference_source = Path(reference)
        self.task = task
        self.rules = Rules(**{f.name: config.get("rules", {}).get(f.name, f.default) for f in fields(Rules)})
        self.halves = split_halves(train, int(config.get("seed", 0)))
        self.proposer = proposer
        self.leakage = Leakage()
        self.log = log
        self.reference_dir = self.run_dir / "reference"
        self.journal_path = self.run_dir / "journal.jsonl"
        self.outcomes: list[Outcome] = []
        self.reference: Measurement | None = None
        self.best_id: str | None = None
        self.turns = 0
        self.empty_turns = 0
        self.gpu_seconds = 0.0
        self.stop_reason: str | None = None
        self.decision: dict[str, Any] | None = None
        self._prepared = False
        if workspace_options is None:
            workspace_options = task.workspace_options(train, self.best, self.leakage.add)
        self.workspace_options = workspace_options

    # -- bookkeeping -------------------------------------------------------------------------------
    def _journal(self, kind: str, **payload: Any) -> None:
        with self.journal_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"type": kind, "time": _now(), **payload}, default=str) + "\n")

    def _known(self) -> dict[str, Path]:
        known = {cand.candidate_id(self.reference_dir): self.reference_dir}
        known.update({o.candidate_id: Path(o.directory) for o in self.outcomes})
        return known

    @property
    def ref(self) -> Measurement:
        """The starting candidate's measurement (measured before anything else needs it)."""
        if self.reference is None:
            raise RuntimeError("the starting candidate has not been measured yet")
        return self.reference

    @property
    def best_cid(self) -> str:
        """The best candidate's id (the starting candidate until another ranks above it)."""
        if self.best_id is None:
            raise RuntimeError("the starting candidate has not been measured yet")
        return self.best_id

    def _score(self, cid: str) -> Measurement:
        if cid == self.reference_id:
            return self.ref
        score = next(o.score for o in self.outcomes if o.candidate_id == cid)
        if score is None:
            raise RuntimeError(f"candidate {cid} has no measurement")
        return score

    def best(self) -> Measurement | None:
        """The measurement of the best candidate so far, or None before the starting candidate is measured."""
        return self._score(self.best_id) if self.best_id else None

    @property
    def reference_id(self) -> str:
        """The starting candidate's id."""
        return cand.candidate_id(self.reference_dir)

    def _save_digests(self, m: Measurement) -> None:
        out = self.run_dir / "measure" / m.label
        out.mkdir(parents=True, exist_ok=True)
        (out / "digests.json").write_text(json.dumps(m.digests, indent=1), encoding="utf-8")
        self.leakage.add(self.task.shown_material(m.digests))

    def _load_run(self, data: dict) -> Measurement:
        m = Measurement.from_dict(data)
        path = self.run_dir / "measure" / m.label / "digests.json"
        if path.is_file():
            m.digests = json.loads(path.read_text(encoding="utf-8"))
            self.leakage.add(self.task.shown_material(m.digests))
        return m

    # -- setup and resume --------------------------------------------------------------------------
    def _preregister(self) -> None:
        shutil.copytree(self.reference_source, self.reference_dir, ignore=shutil.ignore_patterns("__pycache__"))
        prereg = {
            "written": _now(),
            "task": self.task.name,
            "rules": self.rules.text(self.task.scoring(), self.task.unit),
            "rule_values": {f.name: getattr(self.rules, f.name) for f in fields(Rules)},
            "config": self.config,
            "reference": {"source": str(self.reference_source), "candidate_id": self.reference_id},
            "train": self.train,
            "train_halves": self.halves,
            "code_sha256": code_hash(),
        }
        (self.run_dir / "preregistration.json").write_text(json.dumps(prereg, indent=1), encoding="utf-8")
        self.log(f"pre-registered {self.run_dir / 'preregistration.json'}")

    def _resume(self) -> None:
        by_id: dict[str, Outcome] = {}
        for line in self.journal_path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            kind = event["type"]
            if kind == "reference":
                self.reference = self._load_run(event["measurement"])
                self.gpu_seconds += self.reference.seconds
                self.best_id = self.reference_id
            elif kind == "turn":
                self.turns = event["turn"] + 1
                self.gpu_seconds += event.get("seconds", 0.0)
                self.empty_turns = 0 if event.get("submitted") else self.empty_turns + 1
            elif kind == "candidate":
                names = ("turn", "candidate_id", "parent_id", "directory", "rationale", "diff", "auto")
                outcome = Outcome(**{k: event[k] for k in names})
                by_id[outcome.candidate_id] = outcome
                self.outcomes.append(outcome)
            elif kind in ("measured", "remeasured"):
                outcome = by_id[event["candidate_id"]]
                outcome.gates, outcome.failure = event["gates"], event.get("failure")
                if event.get("measurement"):
                    outcome.score = self._load_run(event["measurement"])
                    if kind == "measured":
                        self.gpu_seconds += outcome.score.seconds
                if "best" in event:
                    self.best_id = event["best"]
            elif kind == "rebest":
                self.best_id = event["best"]
            elif kind == "stop":
                self.stop_reason = event["reason"]
            elif kind == "decision":
                self.decision = event["decision"]
        used = self.gpu_seconds / 3600
        self.log(
            f"resumed {self.run_dir.name}: {len(self.outcomes)} candidates, best {str(self.best_id)[:8]}, "
            f"{used:.1f} GPU-hours used"
        )

    # -- measuring ---------------------------------------------------------------------------------
    def _measure(
        self, directory: Path, label: str, *, abort: Callable[[Measurement], bool] | None = None
    ) -> Measurement:
        return self.task.measure(directory, self.halves, self.run_dir / "measure" / label, label=label, abort=abort)

    def _abort(self, m: Measurement) -> bool:
        unit = self.task.unit
        reference_half = self.ref.count(keys(self.halves[0]))[1]
        mine = m.count(m.outcomes)[1]
        self.log(f"  early-abort check: {mine} vs the starting candidate's {reference_half} pairs right on half 1")
        if reference_half - mine >= self.rules.abort_behind:
            m.abort_reason = f"{mine} vs {reference_half} pairs right on half 1"
            return True
        minutes = gpu_seconds(m.cost, self.rules) / 60 / max(1, m.instances)
        limit = self.rules.max_gpu_minutes_per_repo * self.rules.cost_abort_slack
        self.log(f"  cost-abort check: {minutes:.1f} GPU-minutes per {unit} on half 1 (abort above {limit:g})")
        if minutes > limit:
            m.abort_reason = f"{minutes:.1f} GPU-minutes per {unit} on half 1"
            return True
        return False

    def _gates(self, m: Measurement, outcome: Outcome) -> list[str]:
        leaks = self.leakage.check(cand.added_text(outcome.diff))
        return gate_failures(m, self.ref, self.rules, leaks, self.task.unit)

    def _measure_reference(self) -> None:
        self.log("measuring the starting candidate on the training pairs")
        m = self._measure(self.reference_dir, "reference")
        self._save_digests(m)
        self.reference = m
        self.best_id = self.reference_id
        self.gpu_seconds += m.seconds
        self._journal("reference", measurement=m.to_dict())
        hours = gpu_seconds(m.cost, self.rules) / 3600
        self.log(
            f"starting candidate: {m.right}/{m.pairs} pairs right, findings {m.findings}, "
            f"estimated GPU time {hours:.2f} h"
        )

    def _rebest(self, reason: str) -> None:
        best = self.reference_id
        for o in self.outcomes:
            if (
                o.score is not None
                and o.gates == []
                and rank_key(o.score, self.rules) < rank_key(self._score(best), self.rules)
            ):
                best = o.candidate_id
        self.best_id = best
        self._journal("rebest", best=best)
        self.log(f"{reason}: best is now {best[:8]}")

    def _repair_outages(self) -> None:
        """
        Measure again what a model-server outage spoiled, then gate again.

        The task drops the spoiled instances from the runs (`Task.spoiled`) and the measurement resumes, so only those
        are measured again. The repairs are not charged to the budget.
        """
        changed = False
        for o in self.outcomes:
            if o.score is None or o.gates is None:
                continue
            count = self.task.spoiled(o.score)
            if not count:
                continue
            self.log(f"outage repair: {o.label}: measuring {count} instances again")
            new = self._measure(Path(o.directory), o.label, abort=self._abort)
            self._save_digests(new)
            old, o.score = o.score, new
            o.gates = self._gates(new, o)
            self._journal(
                "remeasured",
                candidate_id=o.candidate_id,
                measurement=new.to_dict(),
                gates=o.gates,
                previous=old.to_dict(),
                reason="model-server outage",
                repair_seconds=new.seconds,
            )
            changed = True
        if changed:
            self._rebest("outage repair")

    def _measure_outcome(self, outcome: Outcome) -> None:
        score, failure = None, None
        try:
            score = self._measure(Path(outcome.directory), outcome.label, abort=self._abort)
        except Exception as exc:  # a broken candidate does not end the experiment
            failure = f"{type(exc).__name__}: {exc}"[:500]
        if score is not None:
            self._save_digests(score)
            self.gpu_seconds += score.seconds
        gates = self._gates(score, outcome) if score else ["measurement_failed"]
        outcome.score, outcome.gates, outcome.failure = score, gates, failure
        better = score is not None and rank_key(score, self.rules) < rank_key(self._score(self.best_cid), self.rules)
        if score is not None and not gates and better:
            self.best_id = outcome.candidate_id
        self._journal(
            "measured",
            candidate_id=outcome.candidate_id,
            gates=gates,
            failure=failure,
            measurement=score.to_dict() if score else None,
            best=self.best_id,
        )
        status = "  ELIGIBLE" if not gates else f"  gates: {'; '.join(gates)}"
        self.log(
            f"[{outcome.label}] "
            + (self._headline(score) if score else f"failed: {failure}")
            + status
            + f"  best: {self.best_cid[:8]}"
        )

    # -- the optimizer's context -------------------------------------------------------------------
    def _headline(self, m: Measurement) -> str:
        ref, unit = self.ref, self.task.unit
        minutes = gpu_seconds(m.cost, self.rules) / 60 / max(1, m.instances)
        text = (
            f"{m.right}/{m.pairs} pairs right ({m.right - ref.right:+d} vs the starting candidate), "
            f"{m.strict} strictly, findings {m.findings} ({m.findings / max(1, ref.findings):.2f}x), "
            f"estimated GPU time {minutes:.1f} minutes per {unit}"
        )
        if m.aborted:
            text += ", ABORTED after half 1"
        if m.tool_errors:
            text += f", its code failed on {m.tool_errors} instances"
        return text

    def _static_context(self) -> str:
        ref = self.ref
        half = ref.count(keys(self.halves[0]))[1]
        sizes = ", ".join(f"{k} {len(v)}" for k, v in self.train.items())
        hours = gpu_seconds(ref.cost, self.rules) / 3600
        return "\n".join(
            [
                f"## Starting candidate `{self.reference_id[:8]}`",
                f"Training pairs: {ref.pairs} ({sizes}). {ref.right} right, {ref.strict} strictly. Prompt tokens "
                f"{ref.cost['prompt_tokens']:,.0f}, completion tokens {ref.cost['completion_tokens']:,.0f}, findings "
                f"{ref.findings}, estimated GPU time {hours:.1f} hours.",
                f"Early-abort half: {len(keys(self.halves[0]))} pairs, on which the starting candidate has {half} "
                "right.",
                f"Failure labels of the starting candidate: {json.dumps(label_counts(ref.digests))}",
                "",
                "## Training pair keys (any of them works as the example in your tools)",
                *[f"- {name}: " + ", ".join(sorted(ids)) for name, ids in sorted(self.train.items())],
            ]
        )

    def _outcomes_context(self) -> str:
        lines = ["## Outcomes so far"]
        if not self.outcomes:
            lines.append("No candidate measured yet.")
        for n, o in enumerate(self.outcomes, 1):
            status = "eligible" if not o.gates else "gates: " + "; ".join(o.gates)
            lines.append(f"### {n}. `{o.candidate_id[:8]}` from `{o.parent_id[:8]}`: {status}")
            m = o.score
            lines.append(self._headline(m) if m else f"failed to measure: {o.failure}")
            lines.append(f"Hypothesis: {o.rationale}")
            if m:
                parent = self._score(o.parent_id).outcomes
                won = sorted(k for k, v in m.outcomes.items() if v[1] and k in parent and not parent[k][1])
                lost = sorted(k for k, v in m.outcomes.items() if not v[1] and k in parent and parent[k][1])
                lines.append(f"Versus its parent: now right {won or 'none'}; now wrong {lost or 'none'}.")
                lines.append(f"Failure labels: {json.dumps(label_counts(m.digests))}")
            diff = o.diff if len(o.diff) <= DIFF_CHARS else o.diff[:DIFF_CHARS] + "\n... [diff truncated]"
            lines.append(_fenced(diff or "(no diff)", "diff"))
        return "\n".join(lines)

    def _turn_context(self) -> str:
        best = self._score(self.best_cid)
        remaining = int(self.config["iterations"]) - self.turns
        budget = float(self.config["gpu_hours"])
        draft = self.run_dir / "draft"
        files = [f"### {rel}\n{_fenced((draft / rel).read_text(encoding='utf-8'))}" for rel in cand.files(draft)]
        digests = sorted(best.digests, key=lambda d: (d["labels"][0], d["key"]))
        described = self._headline(best) if self.best_id != self.reference_id else "the starting candidate"
        return "\n".join(
            [
                "## This turn",
                f"Candidates left including this one: {remaining}. GPU budget left: "
                f"{max(0.0, budget - self.gpu_seconds / 3600):.1f} of {budget:g} hours.",
                f"The draft is `{self.best_cid[:8]}`, the best so far ({described}). "
                f"Revision: `{cand.candidate_id(draft)}`.",
                "",
                f"## Failure digests of the draft on the training pairs ({len(digests)} of {best.pairs} pairs not "
                "right)",
                *[self.task.render(d) for d in digests],
                "",
                "## The draft's files",
                *files,
            ]
        )

    def context(self) -> list[str]:
        """The optimizer's messages for a turn, ordered by how often they change."""
        return [self._static_context(), self._outcomes_context(), self._turn_context()]

    # -- the experiment ----------------------------------------------------------------------------
    def prepare(self) -> Measurement:
        """
        Pre-register the experiment and measure the starting candidate, or resume both; returns that measurement.

        `run()` starts with this. Called alone, it leaves an experiment that a later `run()` resumes at its first turn.
        """
        if not self._prepared:
            self.run_dir.mkdir(parents=True, exist_ok=True)
            if self.journal_path.is_file():
                self._resume()
            else:
                self._preregister()
            self.leakage.add(self.task.training_material(self.train))
            self._prepared = True
        if self.reference is None:
            self._measure_reference()
        return self.ref

    def run(self) -> dict[str, Any]:
        """Run or resume the experiment; returns the decision."""
        self.prepare()
        self._repair_outages()
        for outcome in self.outcomes:
            if outcome.gates is None:
                self.log(f"measuring {outcome.label} again: its measurement was interrupted")
                self._measure_outcome(outcome)
        while self.stop_reason is None:
            self.stop_reason = self._stop_reason()
            if self.stop_reason:
                self._journal("stop", reason=self.stop_reason)
                break
            self._turn()
        if self.decision is None:
            self.decision = self._decide()
            self._journal("decision", decision=self.decision)
            (self.run_dir / "decision.json").write_text(json.dumps(self.decision, indent=1), encoding="utf-8")
        return self.decision

    def _stop_reason(self) -> str | None:
        if self.turns >= int(self.config["iterations"]):
            return f"all {self.config['iterations']} candidate turns used"
        if self.gpu_seconds / 3600 >= float(self.config["gpu_hours"]):
            return f"GPU budget of {self.config['gpu_hours']} hours spent"
        if self.empty_turns >= 2:  # noqa: PLR2004 - two turns in a row
            return "two turns in a row without a candidate"
        return None

    def _turn(self) -> None:
        turn = self.turns
        workspace = Workspace(
            self.run_dir / "draft",
            self._known(),
            self.leakage.check,
            min_reasoning_reads=int(self.config.get("min_reasoning_reads", 0)),
            **self.workspace_options,
        )
        workspace.begin_turn(self.best_cid)
        context = self.context()
        self.log(f"[turn {turn}] proposing from {self.best_cid[:8]}")
        submission, info = self.proposer(workspace, context, self.run_dir / "turns" / f"turn-{turn:03d}.json")
        self.turns += 1
        self.gpu_seconds += float(info.get("seconds", 0.0))
        self._journal(
            "turn",
            turn=turn,
            **{
                **info,
                "submitted": submission.candidate_id if submission else None,
                "validation_failures": workspace.validation_failures,
            },
        )
        if submission is None:
            if workspace.finish_reason:
                self.stop_reason = f"the optimizer finished: {workspace.finish_reason}"
                self._journal("stop", reason=self.stop_reason)
            else:
                self.empty_turns += 1
                self.log(f"[turn {turn}] no candidate ({info.get('error') or 'nothing submitted'})")
            return
        self.empty_turns = 0
        outcome = Outcome(
            turn=turn,
            candidate_id=submission.candidate_id,
            parent_id=submission.parent_id,
            directory="",
            rationale=submission.rationale,
            diff=submission.diff,
            auto=submission.auto,
        )
        directory = self.run_dir / "candidates" / outcome.label
        shutil.copytree(workspace.draft, directory, ignore=shutil.ignore_patterns("__pycache__"))
        outcome.directory = str(directory)
        self.outcomes.append(outcome)
        self._journal(
            "candidate",
            turn=turn,
            candidate_id=outcome.candidate_id,
            parent_id=outcome.parent_id,
            directory=outcome.directory,
            rationale=outcome.rationale,
            diff=outcome.diff,
            auto=outcome.auto,
        )
        self.log(f"[turn {turn}] candidate {outcome.label}: {outcome.rationale}")
        self._measure_outcome(outcome)

    def _decide(self) -> dict[str, Any]:
        ref, best = self.ref, self._score(self.best_cid)
        b, c = discordant(best, ref)
        return {
            "written": _now(),
            "stop_reason": self.stop_reason,
            "best": self.best_id,
            "best_directory": str(self._known()[self.best_cid]),
            "train": {
                "best": best.to_dict(),
                "reference": ref.to_dict(),
                "discordant": [b, c],
                "mcnemar_p_one_sided": mcnemar_one_sided(b, c),
            },
            "candidates": [
                {
                    "label": o.label,
                    "candidate_id": o.candidate_id,
                    "directory": o.directory,
                    "eligible": o.gates == [],
                    "pairs_right": o.score.right if o.score else None,
                    "pairs": o.score.pairs if o.score else None,
                    "findings": o.score.findings if o.score else None,
                    "gates": o.gates,
                }
                for o in self.outcomes
            ],
            "next": "Pick among the candidates on the validation pairs, then look at the test pairs once with the one "
            "you picked.",
        }
