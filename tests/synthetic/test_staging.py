# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import os
from pathlib import Path

import pytest

from security_agent.synthetic.staging import DIR_MODE, FILE_MODE, FIXED_MTIME, stage


def _write(path: Path, content: bytes | str, mtime: float | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    if mtime is not None:
        os.utime(path, (mtime, mtime))


def _tree(root: Path, mutated: bool = False) -> Path:
    _write(root / "pyproject.toml", "[project]\nname = 'x'\n", mtime=1_500_000_000)
    _write(root / "src/pkg/component.py", "def run(q):\n    return q\n", mtime=1_500_000_000)
    _write(root / "src/pkg/util.py", "X = 1\n", mtime=1_500_000_000)
    if mutated:
        # What `git apply` does to a planted file: new content, a fresh mtime, a fresh inode.
        (root / "src/pkg/component.py").unlink()
        _write(root / "src/pkg/component.py", "def run(q):\n    return eval(q)\n", mtime=1_700_000_000)
    return root


def _metadata(staged) -> list[tuple[str, int, int]]:
    rows = []
    for dirpath, _, filenames in os.walk(staged.root):
        for name in [*filenames, "."]:
            path = Path(dirpath) / name
            info = path.stat()
            rows.append((path.relative_to(staged.root).as_posix(), int(info.st_mtime), info.st_mode & 0o777))
    return sorted(rows)


def _inode_rank(staged) -> list[str]:
    return sorted(staged.files, key=lambda rel: (staged.root / rel).stat().st_ino)


def test_copies_contents_and_excludes_vcs_bytecode_symlinks(tmp_path):
    source = _tree(tmp_path / "src-tree")
    _write(source / ".git/config", "[core]\n")
    _write(source / "src/pkg/__pycache__/component.cpython-313.pyc", b"\x00\x01")
    _write(source / "src/pkg/stale.pyc", b"\x00\x01")
    _write(source / "data/model.bin", b"\x00binary")
    _write(source / "data/big.txt", "a" * 500)
    _write(source / "data/latin1.txt", "caf\xe9".encode("latin-1"))
    (source / "link.py").symlink_to(source / "src/pkg/util.py")

    staged = stage(source, tmp_path / "stage", max_file_bytes=200)

    assert staged.files == ("pyproject.toml", "src/pkg/component.py", "src/pkg/util.py")
    assert {(w.path, w.reason) for w in staged.withheld} == {
        ("data/model.bin", "binary"),
        ("data/latin1.txt", "binary"),
        ("data/big.txt", "too_large"),
        ("link.py", "symlink"),
    }
    assert (staged.root / "src/pkg/component.py").read_text() == "def run(q):\n    return q\n"
    on_disk = sorted(p.relative_to(staged.root).as_posix() for p in staged.root.rglob("*") if p.is_file())
    assert on_disk == list(staged.files)


def test_metadata_is_constant(tmp_path):
    staged = stage(_tree(tmp_path / "src-tree"), tmp_path / "stage")
    rows = _metadata(staged)
    assert {mtime for _, mtime, _ in rows} == {FIXED_MTIME}
    assert {mode for rel, _, mode in rows if (staged.root / rel).is_file()} == {FILE_MODE}
    assert {mode for rel, _, mode in rows if (staged.root / rel).is_dir()} == {DIR_MODE}


def test_pair_members_are_indistinguishable_by_metadata(tmp_path):
    baseline = stage(_tree(tmp_path / "baseline"), tmp_path / "stage")
    mutant = stage(_tree(tmp_path / "mutant", mutated=True), tmp_path / "stage")

    assert _metadata(baseline) == _metadata(mutant)
    assert _inode_rank(baseline) == _inode_rank(mutant) == sorted(baseline.files)
    assert baseline.files == mutant.files
    assert "baseline" not in str(baseline.root) and "mutant" not in str(mutant.root)


def test_line_count_and_cleanup(tmp_path):
    staged = stage(_tree(tmp_path / "src-tree"), tmp_path / "stage")
    assert staged.line_count("src/pkg/component.py") == 2
    workspace = staged.root.parent
    staged.cleanup()
    assert not workspace.exists()


def test_missing_source_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        stage(tmp_path / "nope", tmp_path)
