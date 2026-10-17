# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Leakage check: does a candidate's added text name training answers?

The optimizer reads failure digests, which show training file paths, repository names, pair titles and code. A
prompt that repeats them raises the training score and nothing else. The check is applied when the optimizer submits,
so a leaking draft is refused before it costs a scan, and again when the candidate is gated.

Checked, case-insensitively, against everything the optimizer has been shown (`digest.shown_material`):
- a planted file's path or basename (`__init__.py` excepted);
- a repository name, as a whole word (names under 4 characters excepted);
- a run of `TITLE_WORDS` words copied from a pair title;
- a run of `CODE_TOKENS` code tokens copied from an excerpt.

Generic security knowledge ("filter values become query operators") is not leakage. The real protection against
overfitting is the held-out validation split; this check catches copying.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

CODE_TOKENS = 10
TITLE_WORDS = 6
GENERIC_BASENAMES = {"__init__.py"}
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]")


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall(text)


def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


class Leakage:
    def __init__(self) -> None:
        self.paths: set[str] = set()
        self.repositories: set[str] = set()
        self.title_grams: dict[tuple[str, ...], str] = {}
        self.code_grams: set[tuple[str, ...]] = set()

    def add(self, shown: dict[str, list[str]]) -> None:
        """Add material the optimizer has been shown (`digest.shown_material`)."""
        for path in shown.get("paths", []):
            self.paths.add(path.lower())
            name = PurePosixPath(path).name.lower()
            if name not in GENERIC_BASENAMES:
                self.paths.add(name)
        self.repositories |= {r.lower() for r in shown.get("repositories", []) if len(r) >= 4}
        for title in shown.get("titles", []):
            words = _words(title)
            for i in range(len(words) - TITLE_WORDS + 1):
                self.title_grams[tuple(words[i : i + TITLE_WORDS])] = title
        for line in shown.get("code", []):
            tokens = _tokens(line)
            for i in range(len(tokens) - CODE_TOKENS + 1):
                self.code_grams.add(tuple(tokens[i : i + CODE_TOKENS]))

    def check(self, text: str) -> list[str]:
        """Human-readable hits in `text`; empty when nothing leaks."""
        hits: set[str] = set()
        lowered = text.lower()
        for path in self.paths:
            if path in lowered:
                hits.add(f"training file name '{path}'")
        for repo in self.repositories:
            if re.search(rf"(?<![a-z0-9_\-]){re.escape(repo)}(?![a-z0-9_\-])", lowered):
                hits.add(f"training repository name '{repo}'")
        words = _words(text)
        for i in range(len(words) - TITLE_WORDS + 1):
            gram = tuple(words[i : i + TITLE_WORDS])
            if gram in self.title_grams:
                hits.add(f"words copied from a training pair title: '{' '.join(gram)}'")
        for line in text.splitlines():
            tokens = _tokens(line)
            for i in range(len(tokens) - CODE_TOKENS + 1):
                gram = tuple(tokens[i : i + CODE_TOKENS])
                if gram in self.code_grams:
                    hits.add(f"code copied from a training excerpt: '{' '.join(gram)}'")
                    break
        return sorted(hits)
