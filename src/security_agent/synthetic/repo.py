# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The repository as the optimizer's code sees it during one scan: `ctx.repo`, read-only text files.

- `repo.files`: repository-relative paths of the text files (sorted);
- `repo.read(path)` / `repo.lines(path)`: file content, or lines (index 0 is line 1);
- `repo.python_files()`: the `.py` paths;
- `repo.ast(path)`: the parsed module, or None if it does not parse (cached);
- `repo.grep(pattern, glob="*.py")`: `(path, line_number, line)` for every line matching a regular expression;
- `repo.functions(path)`: `(name, first_line, last_line)` for every function and method in a Python file.
"""

from __future__ import annotations

import ast as _ast
import fnmatch
import re
from pathlib import Path


class Repo:
    def __init__(self, root: str, files: list[str]) -> None:
        self.root = Path(root)
        self.files = sorted(files)
        self._known = set(self.files)
        self._texts: dict[str, str] = {}
        self._trees: dict[str, _ast.Module | None] = {}

    def _check(self, path: str) -> str:
        if path not in self._known:
            raise KeyError(f"not a file of this repository: {path!r}")
        return path

    def read(self, path: str) -> str:
        """A file's text."""
        if path not in self._texts:
            self._texts[path] = (self.root / self._check(path)).read_text(encoding="utf-8", errors="replace")
        return self._texts[path]

    def lines(self, path: str) -> list[str]:
        """A file's lines (index 0 is line 1)."""
        return self.read(path).splitlines()

    def python_files(self) -> list[str]:
        """The repository's Python files."""
        return [f for f in self.files if f.endswith(".py")]

    def ast(self, path: str) -> _ast.Module | None:
        """A Python file's parsed module, or None."""
        if path not in self._trees:
            try:
                self._trees[path] = _ast.parse(self.read(path))
            except (SyntaxError, ValueError):
                self._trees[path] = None
        return self._trees[path]

    def grep(self, pattern: str, glob: str = "*.py") -> list[tuple[str, int, str]]:
        """Lines matching a regular expression: (path, line, text)."""
        regex = re.compile(pattern)
        hits = []
        for path in self.files:
            if not (fnmatch.fnmatchcase(path, glob) or fnmatch.fnmatchcase(path.rsplit("/", 1)[-1], glob)):
                continue
            for number, line in enumerate(self.lines(path), start=1):
                if regex.search(line):
                    hits.append((path, number, line))
        return hits

    def functions(self, path: str) -> list[tuple[str, int, int]]:
        """A Python file's functions: (name, first line, last line)."""
        tree = self.ast(path)
        if tree is None:
            return []
        return [
            (node.name, node.lineno, node.end_lineno or node.lineno)
            for node in _ast.walk(tree)
            if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef))
        ]


def line_counts(root: Path, files: list[str]) -> dict[str, int]:
    """Lines per file, for checking that a finding's lines exist."""
    counts = {}
    for rel in files:
        try:
            counts[rel] = len((root / rel).read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            continue
    return counts
