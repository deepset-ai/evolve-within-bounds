# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The optimizer's workspace: a draft candidate directory, edited through Haystack tools and submitted as a candidate.

What the tools enforce, and why:

- **Revision tokens.** Every write names the revision it read (the draft's content id); a stale one is refused.
- **Unique exact match.** `edit_file`'s `old` must occur exactly once in the file, or nothing changes.
- **Validate before submit.** The submitted revision must be the validated one: the task's contract check, the
  contract test of the code, and the leakage check. An invalid draft costs a tool call, never a measurement.
- **No duplicates.** A candidate equal to one already measured, or to its parent, is refused.
- **Edit the best.** `begin_turn(base)` resets the draft to the best candidate so far.

A draft is a directory of YAML, prompt files and `tools/<name>.py` code files; `write_file` and `delete_file` create
and remove code files. The task may add tools that try the draft on a training pair (`run_tool`, `trial_scan`) and
show what the agent did on one (`read_reasoning`).
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from haystack.tools import Tool

from security_agent.optimize import candidate as cand

STALE = "Stale or missing expected_revision: pass the revision from your last tool result."
EXAMPLE_KEY = {"type": "string", "description": "A training pair key, as listed in your context."}
CODE_FILE = re.compile(r"tools/[a-z][a-z0-9_]{1,40}\.py")
MAX_ERRORS_SHOWN = 12
NO_OP = "no_op: the draft is its parent unchanged. Only files the agent uses change it."
LEAK = "leakage: {hit}. Teach the agent how to find such defects anywhere; do not name or copy training answers."

# The task's tools: description and parameters. A task can replace them (`Workspace(tool_specs=...)`).
DEFAULT_SPECS: dict[str, dict[str, Any]] = {
    "run_tool": {
        "description": "Run one code file of the draft on a training pair. Model calls are real (a small budget).",
        "parameters": {
            "path": {"type": "string", "description": "tools/<name>.py"},
            "example": EXAMPLE_KEY,
            "arguments": {"type": "object", "description": "The code's arguments, if it takes any."},
        },
        "required": ["path", "example"],
    },
    "trial_scan": {
        "description": "Run the whole draft on one training pair, as a measurement would. The draft must be valid.",
        "parameters": {"example": EXAMPLE_KEY},
        "required": ["example"],
    },
    "read_reasoning": {
        "description": "Read what the agent did on one training pair in the draft's latest measurement.",
        "parameters": {
            "example": EXAMPLE_KEY,
            "side": {"type": "string", "description": "Which member of the pair."},
            "run": {"type": "integer", "description": "Which of the draft's runs, starting at 1 (default 1)."},
        },
        "required": ["example"],
    },
}


@dataclass(frozen=True)
class Submission:
    """A candidate the optimizer submitted."""

    candidate_id: str
    parent_id: str
    rationale: str
    diff: str
    auto: bool = False


def _yaml_problem(text: str) -> str | None:
    try:
        if not isinstance(yaml.safe_load(text), dict):
            return "not a mapping"
    except yaml.YAMLError as exc:
        return str(exc)
    return None


class Workspace:
    """
    The draft candidate and the optimizer's tools on it.

    :param draft: where the draft directory lives.
    :param known: candidate id -> directory of every measured candidate (the starting candidate included).
    :param leakage: returns leakage hits for a text; checked on the lines the draft adds to its parent.
    :param check: the task's contract check, without running code; returns problems.
    :param contract_check: runs the draft's code on a fixture (in the sandbox, when there is one); returns problems.
    :param example_runner: `run_tool(tools_dir, name, example, arguments=...)`.
    :param trial_runner: `trial_scan(draft, example)`.
    :param reasoning_reader: `read_reasoning(example, side, run)`.
    :param tool_specs: descriptions and parameters for those three tools.
    :param min_reasoning_reads: how many pairs' reasoning must be read in a turn before `submit_candidate`.
    :param max_reasoning_reads: how many reads a turn allows.
    """

    MAX_TRIALS = 3

    def __init__(
        self,
        draft: Path,
        known: dict[str, Path],
        leakage: Callable[[str], list[str]],
        *,
        check: Callable[[Path], list[str]] | None = None,
        contract_check: Callable[[Path], list[str]] | None = None,
        example_runner: Callable[..., str] | None = None,
        trial_runner: Callable[[Path, str], str] | None = None,
        reasoning_reader: Callable[[str, str, int], str] | None = None,
        tool_specs: dict[str, dict[str, Any]] | None = None,
        min_reasoning_reads: int = 0,
        max_reasoning_reads: int = 8,
    ) -> None:
        self.draft = Path(draft)
        self.known = known
        self.leakage = leakage
        self.check = check
        self.contract_check = contract_check
        self.example_runner = example_runner
        self.trial_runner = trial_runner
        self.reasoning_reader = reasoning_reader
        self.tool_specs = {**DEFAULT_SPECS, **(tool_specs or {})}
        self.min_reasoning_reads = min_reasoning_reads if reasoning_reader is not None else 0
        self.max_reasoning_reads = max_reasoning_reads
        self.parent_id = ""
        self.reasoning_reads = 0
        self.trial_scans = 0
        self.validated: str | None = None
        self.validation_failures: list[str] = []
        self.submitted: Submission | None = None
        self.finish_reason: str | None = None
        self.edits = 0

    # -- draft state -------------------------------------------------------------------------------
    @property
    def revision(self) -> str:
        """The draft's content id."""
        return cand.candidate_id(self.draft)

    def begin_turn(self, base_id: str) -> None:
        """Reset the draft to the candidate `base_id`."""
        if self.draft.exists():
            shutil.rmtree(self.draft)
        shutil.copytree(self.known[base_id], self.draft, ignore=shutil.ignore_patterns("__pycache__"))
        self.parent_id = base_id
        self.reasoning_reads = 0
        self.trial_scans = 0
        self.validated = None
        self.submitted = None
        self.finish_reason = None
        self.edits = 0

    def _resolve(self, path: str) -> Path | None:
        rel = path.strip().lstrip("./") if path.strip() not in ("", ".") else ""
        target = (self.draft / rel).resolve()
        if self.draft.resolve() not in target.parents or not target.is_file():
            return None
        return target

    def _code_path(self, path: str) -> Path | None:
        rel = path.strip().lstrip("./")
        return self.draft / rel if CODE_FILE.fullmatch(rel) else None

    def _diff(self) -> str:
        return cand.diff(self.known[self.parent_id], self.draft)

    def _changed(self, current: str) -> str:
        self.validated = None
        self.edits += 1
        revision = self.revision
        if revision == current:
            note = "the edit changed only formatting or a comment; this is not a new candidate"
            return json.dumps({"ok": True, "revision": revision, "note": note})
        return json.dumps({"ok": True, "revision": revision})

    # -- tool functions ----------------------------------------------------------------------------
    def list_files(self) -> str:
        """The draft's files and its revision."""
        return json.dumps({"revision": self.revision, "files": cand.files(self.draft)})

    def read_file(self, path: str) -> str:
        """One file of the draft."""
        target = self._resolve(path)
        if target is None:
            return json.dumps({"error": f"no such file '{path}'; call list_files", "files": cand.files(self.draft)})
        return json.dumps({"revision": self.revision, "path": path, "content": target.read_text(encoding="utf-8")})

    def edit_file(self, path: str, old: str, new: str, expected_revision: str = "") -> str:
        """Replace one exact, unique occurrence of `old` in a file."""
        current = self.revision
        if expected_revision != current:
            return json.dumps({"ok": False, "error": STALE, "revision": current})
        target = self._resolve(path)
        if target is None:
            return json.dumps({"ok": False, "error": f"no such file '{path}'", "files": cand.files(self.draft)})
        text = target.read_text(encoding="utf-8")
        count = text.count(old) if old else 0
        if count == 0:
            error = "old text not found; copy it exactly from the file, including indentation and line breaks."
            return json.dumps({"ok": False, "error": error, "revision": current})
        if count > 1:
            error = f"old text occurs {count} times; include more surrounding text so it matches once."
            return json.dumps({"ok": False, "error": error, "revision": current})
        updated = text.replace(old, new, 1)
        if target.suffix in (".yaml", ".yml") and (problem := _yaml_problem(updated)):
            error = f"the edit would make {target.name} invalid YAML ({problem}); nothing changed"
            return json.dumps({"ok": False, "error": error, "revision": current})
        target.write_text(updated, encoding="utf-8")
        return self._changed(current)

    def write_file(self, path: str, content: str, expected_revision: str = "") -> str:
        """Create or replace a code file `tools/<name>.py`."""
        current = self.revision
        if expected_revision != current:
            return json.dumps({"ok": False, "error": STALE, "revision": current})
        target = self._code_path(path)
        if target is None:
            error = (
                "write_file only creates or replaces tools/<name>.py (lowercase name); use edit_file for other files."
            )
            return json.dumps({"ok": False, "error": error})
        target.parent.mkdir(exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return self._changed(current)

    def delete_file(self, path: str, expected_revision: str = "") -> str:
        """Delete a code file `tools/<name>.py`."""
        current = self.revision
        if expected_revision != current:
            return json.dumps({"ok": False, "error": STALE, "revision": current})
        target = self._code_path(path)
        if target is None or not target.is_file():
            return json.dumps({"ok": False, "error": f"no code file '{path}'; only tools/<name>.py can be deleted"})
        target.unlink()
        return self._changed(current)

    def run_tool(self, path: str, example: str, arguments: dict | str | None = None) -> str:
        """Run one code file of the draft on a training pair (the task's `example_runner`)."""
        target = self._code_path(path)
        if target is None or not target.is_file():
            return json.dumps({"ok": False, "error": f"no code file '{path}'"})
        if self.example_runner is None:
            return json.dumps({"ok": False, "error": "no examples available"})
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments or "{}")
            except ValueError:
                return json.dumps({"ok": False, "error": "arguments must be a JSON object"})
        return self.example_runner(self.draft / "tools", target.stem, example, arguments=arguments or {})

    def trial_scan(self, example: str) -> str:
        """Run the whole (valid) draft on one training pair. At most `MAX_TRIALS` per turn."""
        if self.trial_runner is None:
            return json.dumps({"ok": False, "error": "no trial scans in this experiment"})
        if self.trial_scans >= self.MAX_TRIALS:
            error = f"at most {self.MAX_TRIALS} trial scans per turn; decide with what you have"
            return json.dumps({"ok": False, "error": error})
        checked = json.loads(self.validate_candidate())
        if not checked.get("valid"):
            return json.dumps(
                {"ok": False, "error": "the draft is not valid; fix it first", "errors": checked.get("errors")}
            )
        self.trial_scans += 1
        return self.trial_runner(self.draft, example)

    def read_reasoning(self, example: str, side: str = "vulnerable", run: int = 1) -> str:
        """What the agent did on one training pair (the task's `reasoning_reader`)."""
        if self.reasoning_reader is None:
            return json.dumps({"ok": False, "error": "no reasoning available in this experiment"})
        if self.reasoning_reads >= self.max_reasoning_reads:
            error = f"at most {self.max_reasoning_reads} reasoning reads per turn; decide with what you have"
            return json.dumps({"ok": False, "error": error})
        self.reasoning_reads += 1
        return self.reasoning_reader(example, side, run)

    def validate_candidate(self) -> str:
        """The contract, the contract test and the leakage check, in that order."""
        revision = self.revision
        errors = self.check(self.draft) if self.check else []
        if not errors and revision == self.parent_id:
            errors = [NO_OP]
        if not errors and self.contract_check:
            errors = self.contract_check(self.draft)
        if not errors:
            errors = [LEAK.format(hit=hit) for hit in self.leakage(cand.added_text(self._diff()))]
        if errors:
            self.validation_failures.extend(errors)
            return json.dumps({"valid": False, "revision": revision, "errors": errors[:MAX_ERRORS_SHOWN]})
        self.validated = revision
        return json.dumps({"valid": True, "revision": revision})

    def submit_candidate(self, rationale: str, expected_revision: str = "") -> str:
        """Submit the validated draft; this ends the turn."""
        # The optimizer must look at why the agent failed, not only at what it reported. The fallback auto-submit is
        # exempt, so a turn that never reads still yields its valid draft.
        if self.reasoning_reads < self.min_reasoning_reads:
            error = (
                f"read the reasoning of at least {self.min_reasoning_reads} training pairs first "
                f"({self.reasoning_reads} so far): call read_reasoning on pairs that stand for the pattern your "
                "change addresses, check that the reasoning supports your hypothesis, then submit again"
            )
            return json.dumps({"ok": False, "error": error})
        return self._submit(rationale, expected_revision, auto=False)

    def _submit(self, rationale: str, expected_revision: str, *, auto: bool) -> str:
        revision = self.revision
        if expected_revision != revision:
            return json.dumps({"ok": False, "error": STALE})
        if self.validated != revision:
            return json.dumps({"ok": False, "error": "Not validated: call validate_candidate on this revision first."})
        if not rationale.strip():
            return json.dumps({"ok": False, "error": "State the hypothesis this candidate tests."})
        if revision in self.known:
            error = "duplicate_or_no_op: this candidate was already measured. Change something."
            return json.dumps({"ok": False, "error": error})
        self.submitted = Submission(
            candidate_id=revision, parent_id=self.parent_id, rationale=rationale.strip(), diff=self._diff(), auto=auto
        )
        return json.dumps({"ok": True, "candidate_id": revision})

    def finish(self, reason: str) -> str:
        """Stop without submitting."""
        if not reason.strip():
            return json.dumps({"ok": False, "error": "Say why you are stopping."})
        self.finish_reason = reason.strip()
        return json.dumps({"ok": True})

    def auto_submit(self, hint: str) -> Submission | None:
        """Submit an edited, valid draft when the turn ended without `submit_candidate` (the edit is the hypothesis)."""
        if self.revision == self.parent_id or self.revision in self.known:
            return None
        if not json.loads(self.validate_candidate()).get("valid"):
            return None
        stated = hint.strip()[:400] or "no hypothesis stated"
        self._submit(
            f"[auto-submitted: the optimizer edited the draft but did not submit it] {stated}", self.revision, auto=True
        )
        return self.submitted

    # -- tools -------------------------------------------------------------------------------------
    def _task_tool(self, name: str, function: Callable[..., str]) -> Tool:
        spec = self.tool_specs[name]
        parameters = {"type": "object", "properties": spec["parameters"], "required": spec["required"]}
        return Tool(name=name, description=spec["description"], parameters=parameters, function=function)

    def tools(self) -> list[Tool]:
        """The optimizer's tools for this turn."""
        revision = {"type": "string", "description": "The revision from your last tool result."}
        no_parameters = {"type": "object", "properties": {}, "required": []}
        tools = [
            Tool(
                name="list_files",
                description="List the draft candidate's files, with the current revision.",
                parameters=no_parameters,
                function=self.list_files,
            ),
            Tool(
                name="read_file",
                description="Read one file of the draft candidate. Returns JSON with 'revision' and 'content'.",
                parameters={
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "e.g. 'pipeline.yaml', 'prompts/system.md' or 'tools/search.py'.",
                        }
                    },
                },
                function=self.read_file,
            ),
            Tool(
                name="edit_file",
                description="Replace one exact, unique occurrence of text in one file of the draft. Refuses stale "
                "revisions and ambiguous matches. Keep each edit small: several small edits are safer than "
                "one long one.",
                parameters={
                    "type": "object",
                    "required": ["path", "old", "new", "expected_revision"],
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "File to edit, e.g. 'pipeline.yaml' or 'prompts/system.md'.",
                        },
                        "old": {
                            "type": "string",
                            "description": "Exact text to replace; must occur exactly once. Copy it "
                            "from the file, indentation included.",
                        },
                        "new": {"type": "string", "description": "Replacement text."},
                        "expected_revision": revision,
                    },
                },
                function=self.edit_file,
            ),
            Tool(
                name="write_file",
                description="Create or replace a code file tools/<name>.py with the full content. Only code files; "
                "edit the YAML and the prompts with edit_file.",
                parameters={
                    "type": "object",
                    "required": ["path", "content", "expected_revision"],
                    "properties": {
                        "path": {"type": "string", "description": "tools/<name>.py, lowercase name."},
                        "content": {"type": "string", "description": "The complete Python source."},
                        "expected_revision": revision,
                    },
                },
                function=self.write_file,
            ),
            Tool(
                name="delete_file",
                description="Delete a code file tools/<name>.py.",
                parameters={
                    "type": "object",
                    "required": ["path", "expected_revision"],
                    "properties": {"path": {"type": "string"}, "expected_revision": revision},
                },
                function=self.delete_file,
            ),
        ]
        if self.example_runner is not None:
            tools.append(self._task_tool("run_tool", self.run_tool))
        if self.trial_runner is not None:
            tools.append(self._task_tool("trial_scan", self.trial_scan))
        if self.reasoning_reader is not None:
            tools.append(self._task_tool("read_reasoning", self.read_reasoning))
        tools += [
            Tool(
                name="validate_candidate",
                description="Check the draft against the contract, run its code on a small fixture, and apply the "
                "leakage rule. Must succeed on the revision you submit.",
                parameters=no_parameters,
                function=self.validate_candidate,
            ),
            Tool(
                name="submit_candidate",
                description="Submit the validated draft to be measured on the training pairs. This ends your turn.",
                parameters={
                    "type": "object",
                    "required": ["rationale", "expected_revision"],
                    "properties": {
                        "rationale": {
                            "type": "string",
                            "description": "One or two sentences: the hypothesis this "
                            "candidate tests and the evidence behind it.",
                        },
                        "expected_revision": revision,
                    },
                },
                function=self.submit_candidate,
            ),
            Tool(
                name="finish",
                description="Stop without submitting. Only when no hypothesis is left that is worth a measurement.",
                parameters={
                    "type": "object",
                    "required": ["reason"],
                    "properties": {
                        "reason": {"type": "string", "description": "Why no further candidate is worth measuring."}
                    },
                },
                function=self.finish,
            ),
        ]
        return tools
