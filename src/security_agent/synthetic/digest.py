# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Training-only failure digests: what the optimizer learns from a measurement.

Every planted training pair the candidate gets wrong gets a digest. A pair is right when a finding lies within 2 lines
of the planted lines in the vulnerable repository, whatever its CWE, and no finding lies within 2 lines of the
corresponding lines of the safe twin. A digest holds:
- labels saying why the pair failed;
- the planted lines and their safe twin, line-numbered;
- what the scanner reported there;
- what the agent reported nearby, before later steps, and what each of the candidate's steps received and passed on;
- what the agent did: why it stopped, its steps and tool calls, which lines of the planted file it read.

The agent's full conversation is not in the digest; the optimizer reads it per pair with `read_reasoning`
(`security_agent.synthetic.traces`).

Labels (one pair can have several):
- `missed`: nothing reported in the planted file of the vulnerable repository;
- `wrong_lines_near` / `wrong_lines_far`: reported in that file, but outside the 2-line tolerance, by at most `NEAR`
  lines or by more;
- `safe_twin_flagged`: a finding at the corresponding lines of the safe twin;
- `reported_then_dropped`: the agent reported the right lines, but a later step, or the normalizer's
  one-finding-per-location rule, removed or moved the finding.

Digests are built only from the training split. They are the only answer material the optimizer sees, so the
leakage check (`security_agent.optimize.leakage`) is built from exactly what they contain.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from security_agent.synthetic.bench.pairs import is_planted, pair_targets
from security_agent.synthetic.bench.runner import load_journal

TOLERANCE = 2  # the scorer's line tolerance
NEAR = 10
EXCERPT_CONTEXT = 4
EXCERPT_MAX = 24
EXPLAIN_CHARS = 110


def _gap(start: int, end: int, lo: int, hi: int) -> int:
    return max(0, lo - end, start - hi)


def _excerpt(root: Path, path: str, start: int, end: int) -> list[list]:
    target = root / path
    if not target.is_file():
        return []
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    lo, hi = (
        max(1, start - EXCERPT_CONTEXT),
        min(len(lines), end + EXCERPT_CONTEXT, start - EXCERPT_CONTEXT + EXCERPT_MAX - 1),
    )
    return [[n, lines[n - 1], start <= n <= end] for n in range(lo, hi + 1)]


def _finding(f: Any, explain: bool = False) -> dict[str, Any]:
    get = f.get if isinstance(f, dict) else (lambda k, d=None: getattr(f, k, d))
    out = {k: get(k) for k in ("path", "line_start", "line_end", "cwe", "title", "confidence")}
    if explain:  # the agent's own explanation of the finding: the missing control
        out.update({k: str(get(k) or "")[:EXPLAIN_CHARS] for k in ("sink", "missing_control") if get(k)})
    return out


def _near(items: list[dict], path: str, lo: int, hi: int, within: int) -> list[dict]:
    return [
        i for i in items if i.get("path") == path and _gap(int(i["line_start"]), int(i["line_end"]), lo, hi) <= within
    ]


def _step_effects(
    mutant: dict, baseline: dict, path: str, mutant_lines: tuple[int, int], baseline_lines: tuple[int, int]
) -> list[dict]:
    """
    What each of the candidate's steps received and passed on near the planted lines, in both repositories.

    Near the planted lines in the vulnerable repository, at the corresponding lines in the safe twin. Both scans ran
    the same pipeline, so steps pair up by position.
    """
    twins = baseline.get("components", [])
    out = []
    for i, r in enumerate(mutant.get("components", [])):
        twin = twins[i] if i < len(twins) else {}
        out.append(
            {
                "component": r.get("component"),
                "ok": r.get("ok"),
                "error": str(r.get("error") or "")[-200:] or None,
                "twin_ok": twin.get("ok"),
                "received": _near(r.get("received", []), path, *mutant_lines, NEAR)[:4],
                "passed": _near(
                    r.get("passed", r.get("received", []) if not r.get("ok") else []), path, *mutant_lines, NEAR
                )[:4],
                "received_twin": _near(twin.get("received", []), path, *baseline_lines, TOLERANCE)[:3],
                "passed_twin": _near(
                    twin.get("passed", twin.get("received", []) if not twin.get("ok") else []),
                    path,
                    *baseline_lines,
                    TOLERANCE,
                )[:3],
            }
        )
    return out


def _ranges(reads: list[dict], path: str) -> list[list[int]]:
    merged: list[list[int]] = []
    for lo, hi in sorted((int(r["start"]), int(r["end"])) for r in reads if r.get("path") == path):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return merged


def _agent_view(mutant: dict, baseline: dict, path: str, lines: tuple[int, int]) -> dict:
    """What the agent did in each repository of the pair, and with the planted file."""
    view = {}
    for member, record in (("vulnerable", mutant), ("safe_twin", baseline)):
        agent = record.get("agent") or {}
        reads = _ranges(agent.get("reads", []), path)
        view[member] = {
            "stop": agent.get("stop"),
            "steps": agent.get("steps"),
            "reported": len(agent.get("reported", [])),
            "tool_calls": dict(Counter(c.get("tool") for c in agent.get("tool_calls", []))),
            "reads": reads,
            "planted_read": any(lo <= lines[0] and lines[1] <= hi for lo, hi in reads),
        }
    return view


def pair_digest(
    benchmark: str,
    row: dict[str, Any],
    pair: dict[str, Any],
    roots: dict[str, Path],
    reported: dict[str, list[dict]],
    records: dict[str, dict],
) -> dict[str, Any]:
    """Digest of one pair. `roots`, `reported` and `records` are keyed by 'mutant' / 'baseline'."""
    targets = pair_targets(pair)
    labels: list[str] = []
    if row.get("baseline_mapped_localization_alarm"):
        labels.append("safe_twin_flagged")
    if not row.get("mutant_localized"):
        gaps = [
            _gap(int(f["line_start"]), int(f["line_end"]), t["mutant_line_start"], t["mutant_line_end"])
            for t in targets
            for f in reported["mutant"]
            if f["path"] == t["path"]
        ]
        labels.append("missed" if not gaps else ("wrong_lines_near" if min(gaps) <= NEAR else "wrong_lines_far"))
        by_agent = (records.get("mutant") or {}).get("candidates", [])
        if any(_near(by_agent, t["path"], t["mutant_line_start"], t["mutant_line_end"], TOLERANCE) for t in targets):
            labels.append("reported_then_dropped")

    shown = []
    for t in targets[:2]:
        m_lo, m_hi, b_lo, b_hi = (
            t["mutant_line_start"],
            t["mutant_line_end"],
            t["baseline_line_start"],
            t["baseline_line_end"],
        )
        mutant_record, baseline_record = records.get("mutant") or {}, records.get("baseline") or {}
        shown.append(
            {
                "path": t["path"],
                "mutant_lines": [m_lo, m_hi],
                "baseline_lines": [b_lo, b_hi],
                "mutant_excerpt": _excerpt(roots["mutant"], t["path"], m_lo, m_hi),
                "baseline_excerpt": _excerpt(roots["baseline"], t["path"], b_lo, b_hi),
                "reported_mutant": [f for f in reported["mutant"] if f["path"] == t["path"]][:6],
                "reported_baseline": _near(reported["baseline"], t["path"], b_lo, b_hi, TOLERANCE)[:4],
                "agent_mutant": [
                    _finding(c, explain=True)
                    for c in _near(mutant_record.get("candidates", []), t["path"], m_lo, m_hi, NEAR)
                ][:5],
                "agent_baseline": [
                    _finding(c, explain=True)
                    for c in _near(baseline_record.get("candidates", []), t["path"], b_lo, b_hi, TOLERANCE)
                ][:3],
                "steps": _step_effects(mutant_record, baseline_record, t["path"], (m_lo, m_hi), (b_lo, b_hi)),
                "agent": _agent_view(mutant_record, baseline_record, t["path"], (m_lo, m_hi)),
            }
        )
    return {
        "key": f"{benchmark}/{row['pair_id']}",
        "repository": pair.get("repository", ""),
        "cwe": pair.get("cwe", row.get("cwe")),
        "title": pair.get("title", ""),
        "labels": labels or ["other"],
        "multi_file": bool(pair.get("multi_file")),
        "targets": shown,
    }


def build_digests(
    benchmark: str, run_dir: Path, score_rows: list[dict], pairs: dict[str, dict], instance_paths: dict[str, Path]
) -> list[dict]:
    """Digests for the planted pairs among `score_rows` that are wrong, from one run directory of the measurement."""
    journal = load_journal(run_dir / "reports.jsonl")
    out = []
    for row in score_rows:
        if (
            row.get("pair_localized_correct")
            or row.get("pair_class", "planted") != "planted"
            or not is_planted(pairs[row["pair_id"]])
        ):
            continue
        pair = pairs[row["pair_id"]]
        ids = {"mutant": pair["mutant_instance_id"], "baseline": pair["baseline_instance_id"]}
        reported, records = {}, {}
        for member, iid in ids.items():
            report = journal.get(iid)
            reported[member] = [_finding(f) for f in (report.findings if report else [])]
            record = run_dir / "records" / f"{iid}.json"
            records[member] = json.loads(record.read_text(encoding="utf-8")) if record.is_file() else {}
        out.append(pair_digest(benchmark, row, pair, {m: instance_paths[i] for m, i in ids.items()}, reported, records))
    return out


def label_counts(digests: list[dict]) -> dict[str, int]:
    """How often each failure label occurs."""
    return dict(sorted(Counter(label for d in digests for label in d["labels"]).items()))


def _code(rows: list[list]) -> str:
    return "\n".join(f"{'>' if hit else ' '} {n:>5} | {text}" for n, text, hit in rows) or "  (file not shown)"


def _items(items: list[dict]) -> str:
    if not items:
        return "none"
    return "; ".join(
        f"lines {i['line_start']}-{i['line_end']} {i.get('cwe')}"
        + (f" conf {i['confidence']}" if i.get("confidence") is not None else "")
        + (f' "{str(i.get("title") or "")[:80]}"' if i.get("title") else "")
        + (
            f" (sink: {i['sink']}" + (f"; missing: {i['missing_control']}" if i.get("missing_control") else "") + ")"
            if i.get("sink")
            else (f" (explanation: {i['missing_control']})" if i.get("missing_control") else "")
        )
        for i in items
    )


def render(digest: dict[str, Any]) -> str:
    """One failure digest as text for the optimizer."""
    title = f' "{digest["title"]}"' if digest.get("title") else ""
    lines = [
        f"### {digest['key']} ({digest['repository']}): planted {digest['cwe']}{title}; "
        f"labels: {', '.join(digest['labels'])}"
    ]
    for t in digest["targets"]:
        lines.append(f"Vulnerable repository, `{t['path']}` (planted lines marked >):")
        lines.append(_code(t["mutant_excerpt"]))
        lines.append("Safe twin, same file (corresponding lines marked >):")
        lines.append(_code(t["baseline_excerpt"]))
        lines.append(f"- Reported in this file (vulnerable repo): {_items(t['reported_mutant'])}")
        lines.append(f"- Reported at the corresponding lines (safe twin): {_items(t['reported_baseline'])}")
        for member, label in (("vulnerable", "vulnerable repo"), ("safe_twin", "safe twin")):
            a = t["agent"][member]
            tools = ", ".join(f"{k} {v}" for k, v in sorted(a["tool_calls"].items())) or "none"
            lines.append(
                f"- The agent ({label}): stopped ({a['stop']}) after {a['steps']} steps; {a['reported']} findings "
                f"reported in the whole repository; tool calls: {tools}"
            )
        a = t["agent"]["vulnerable"]
        lines.append(
            "- The agent read this file (vulnerable repo): "
            + (
                ", ".join(f"lines {lo}-{hi}" for lo, hi in a["reads"])
                + ("; the planted lines were read" if a["planted_read"] else "; the planted lines were NOT read")
                if a["reads"]
                else "never"
            )
        )
        lines.append(
            f"- Reported by the agent (before your later steps) within {NEAR} lines (vulnerable repo): "
            f"{_items(t['agent_mutant'])}"
        )
        if t["agent_baseline"]:
            lines.append(
                f"- Reported by the agent (before your later steps) at the corresponding lines (safe twin): "
                f"{_items(t['agent_baseline'])}"
            )
        for c in t["steps"]:
            failed = "" if c["ok"] else f" [FAILED, passed its input on unchanged: {c['error']}]"
            twin_failed = "" if c["twin_ok"] in (True, None) else " [FAILED on the safe twin]"
            lines.append(
                f"- Your step `{c['component']}`{failed}{twin_failed}: vulnerable repo, received "
                f"{_items(c['received'])}; passed on {_items(c['passed'])}. Safe twin at the corresponding lines: "
                f"received {_items(c['received_twin'])}; passed on {_items(c['passed_twin'])}"
            )
    if digest.get("multi_file"):
        lines.append("(multi-file pair: a hit on any planted target counts)")
    return "\n".join(lines)


def shown_material(digests: list[dict]) -> dict[str, list[str]]:
    """What the optimizer was shown, for the leakage check: paths, repositories, titles and code lines."""
    paths, repos, titles, code = set(), set(), set(), []
    for d in digests:
        repos.add(d["repository"])
        if d.get("title"):
            titles.add(d["title"])
        for t in d["targets"]:
            paths.add(t["path"])
            code += [text for _, text, _ in t["mutant_excerpt"] + t["baseline_excerpt"]]
    return {"paths": sorted(paths), "repositories": sorted(repos), "titles": sorted(titles), "code": code}
