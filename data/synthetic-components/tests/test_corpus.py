from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest

from haystack_component_vulnerability_benchmark.catalog import (
    corpus_root,
    load_repositories,
    repository_tree,
    tree_digest,
    walk_tree,
)
from haystack_component_vulnerability_benchmark.validate import CORPUS_BYTE_BUDGET


def test_every_tree_matches_its_recorded_digest(root: Path) -> None:
    for repository in load_repositories(root):
        digest, count = tree_digest(repository_tree(root, repository))
        assert digest == repository["tree_sha256"], repository["name"]
        assert count == repository["file_count"], repository["name"]


def test_no_tree_contains_a_git_directory(root: Path) -> None:
    assert not list(corpus_root(root).glob("*/.git"))


def test_corpus_is_portable(root: Path) -> None:
    """CRLF, case collisions and odd characters all break digests or checkouts."""
    for repository in load_repositories(root):
        tree = repository_tree(root, repository)
        folded: dict[str, str] = {}
        for relative in walk_tree(tree):
            text = str(relative)
            assert ":" not in text, text
            previous = folded.setdefault(text.casefold(), text)
            assert previous == text, f"case collision: {previous} vs {text}"
            path = tree / text
            if not path.is_symlink():
                assert b"\r\n" not in path.read_bytes(), text


def test_no_escaping_symlinks(root: Path) -> None:
    for repository in load_repositories(root):
        tree = repository_tree(root, repository)
        for relative in walk_tree(tree):
            path = tree / str(relative)
            if path.is_symlink():
                assert not Path(path.readlink()).is_absolute()


def test_every_python_file_parses(root: Path) -> None:
    for path in corpus_root(root).rglob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_corpus_fits_the_wheel_budget(root: Path) -> None:
    total = sum(
        (corpus_root(root) / str(relative)).stat().st_size
        for relative in walk_tree(corpus_root(root))
    )
    assert total <= CORPUS_BYTE_BUDGET


def test_corpus_files_are_tracked_and_not_ignored(root: Path) -> None:
    probe = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode:
        pytest.skip("not a git work tree")
    tracked = set(
        subprocess.run(
            ["git", "-C", str(root), "ls-files", "--", "corpus"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
    )
    on_disk = {f"corpus/{relative}" for relative in walk_tree(corpus_root(root))}
    assert on_disk - tracked == set(), "untracked corpus files would not reach other machines"


def test_boilerplate_conformance(root: Path) -> None:
    """Every tree's scaffolding must match tools/canon after token substitution."""
    script = root / "tools/scaffold.py"
    if not script.is_file():
        pytest.skip("scaffolder is not present in this distribution")
    result = subprocess.run(
        ["python3", str(script), "check"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout
