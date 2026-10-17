# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
A check of the optimizer's code before it ever runs: syntax, shape and allowed constructs, from the syntax tree.

Every file the optimizer writes is `tools/<name>.py` and declares what it is:
- `KIND = "tool"` with `run(ctx, ...)`: a tool the agent can call;
- `KIND = "step"` with `run(ctx)`: a pipeline step before or after the agent.

The code may use the standard library's text and analysis modules and nothing that reaches outside the repository
it is given: no os, sys, pathlib, io, network or subprocess modules, no open(), eval(), exec() or getattr(), no dunder
attributes. It reads the repository through `ctx.repo`. This keeps code from reading other files (the benchmark's
answer key among them) by accident; the isolation itself is the OpenShell sandbox the scans run in.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

KINDS = {"tool": "run(ctx, ...)", "step": "run(ctx)"}
NAME = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
MAX_LINES, MAX_CHARS = 600, 40_000
ALLOWED_IMPORTS = {
    "ast",
    "re",
    "json",
    "math",
    "itertools",
    "collections",
    "functools",
    "fnmatch",
    "string",
    "textwrap",
    "typing",
    "dataclasses",
    "enum",
    "keyword",
    "token",
    "difflib",
    "bisect",
    "heapq",
    "operator",
    "statistics",
    "unicodedata",
    "copy",
    "abc",
    "numbers",
    "types",
}
BANNED_NAMES = {
    "__import__",
    "eval",
    "exec",
    "compile",
    "breakpoint",
    "input",
    "importlib",
    "globals",
    "vars",
    "__builtins__",
    "open",
    "getattr",
    "setattr",
    "delattr",
    "memoryview",
}
# Process control and file changes: the code analyzes text and has no reason to touch these.
BANNED_ATTRS = {
    "os",
    "sys",
    "system",
    "popen",
    "fork",
    "forkpty",
    "kill",
    "killpg",
    "unlink",
    "rmtree",
    "rmdir",
    "chmod",
    "chown",
    "putenv",
    "environ",
    "execv",
    "execve",
    "execl",
    "execlp",
    "execvp",
    "spawnv",
    "spawnl",
    "posix_spawn",
    "write_text",
    "write_bytes",
    "symlink_to",
    "hardlink_to",
    "mkdir",
    "touch",
    "rename",
    "replace_file",
}


def check_code(path: Path) -> tuple[str | None, list[str]]:
    """(KIND, problems) of one code file; the code is never executed here. Problems are empty when the file is fine."""
    path = Path(path)
    rel = f"tools/{path.name}"
    if not NAME.match(path.stem) or path.suffix != ".py":
        return None, [f"{rel}: code files are tools/<name>.py with a lowercase name (letters, digits, underscores)"]
    text = path.read_text(encoding="utf-8")
    problems = []
    if len(text) > MAX_CHARS or text.count("\n") > MAX_LINES:
        problems.append(f"{rel}: at most {MAX_LINES} lines and {MAX_CHARS} characters")
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return None, problems + [f"{rel}: syntax error: {exc}"]
    kind = None
    for statement in tree.body:
        if not isinstance(statement, ast.Assign) or not isinstance(statement.value, ast.Constant):
            continue
        names_kind = any(isinstance(t, ast.Name) and t.id == "KIND" for t in statement.targets)
        if names_kind and isinstance(statement.value.value, str) and statement.value.value in KINDS:
            kind = statement.value.value
    run = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run"), None)
    if kind is None:
        problems.append(f"{rel}: needs a module-level KIND = one of {sorted(KINDS)}")
    elif (
        run is None
        or not run.args.args
        or run.args.args[0].arg != "ctx"
        or (kind == "step" and len(run.args.args) != 1)
    ):
        problems.append(f"{rel}: KIND {kind!r} needs a top-level function {KINDS[kind]}")
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            modules = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for module in modules:
                if module.split(".")[0] not in ALLOWED_IMPORTS:
                    problems.append(f"{rel}: import of {module!r} is not allowed; allowed: {sorted(ALLOWED_IMPORTS)}")
        elif isinstance(node, ast.Name) and node.id in BANNED_NAMES:
            problems.append(f"{rel}: {node.id!r} is not allowed")
        elif (
            isinstance(node, ast.Attribute) and node.attr.startswith("__") and node.attr not in ("__init__", "__name__")
        ):
            problems.append(f"{rel}: dunder attribute access ({node.attr}) is not allowed")
        elif isinstance(node, ast.Attribute) and node.attr in BANNED_ATTRS:
            problems.append(f"{rel}: attribute {node.attr!r} is not allowed (no process control or file changes)")
    return kind, sorted(set(problems))
