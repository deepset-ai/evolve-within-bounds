# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Leak-free staging of one benchmark instance.

A benchmark instance can leak its label through filesystem metadata: a planted file with a newer modification time,
or a patched file with the highest inode. It can also leak through its surroundings: sibling instances, the answer
key, and the benchmark repository itself.

`stage` copies only file *contents* into a fresh directory:
- in sorted path order, so creation (and inode) order is a function of the path set alone;
- with one constant mtime/atime and one permission mode everywhere;
- without VCS directories, bytecode or symlinks.

Binary and oversized files are withheld: they are listed, but not copied and not readable.
Two members of a pair therefore differ only in the bytes of the files that differ.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

# 2001-09-09T01:46:40Z, the constant hvbench's materializer uses.
FIXED_MTIME = 1_000_000_000
FILE_MODE = 0o644
DIR_MODE = 0o755
MAX_FILE_BYTES = 1_000_000
EXCLUDED_DIRS = frozenset({".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"})
EXCLUDED_SUFFIXES = frozenset({".pyc", ".pyo"})
_BINARY_SNIFF_BYTES = 8192


@dataclass(frozen=True)
class WithheldFile:
    path: str
    size: int
    reason: str  # "binary" | "too_large" | "symlink" | "special"


@dataclass(frozen=True)
class StagedRepo:
    """A staged copy of one instance. The agent sees `root` as `/repo` and never sees the host path."""

    root: Path
    files: tuple[str, ...]
    withheld: tuple[WithheldFile, ...]

    def line_count(self, rel_path: str) -> int:
        """How many lines a staged file has."""
        with (self.root / rel_path).open("rb") as handle:
            return sum(1 for _ in handle)

    def cleanup(self) -> None:
        """Delete the staged copy."""
        shutil.rmtree(self.root.parent, ignore_errors=True)


def stage(source: Path, parent: Path | None = None, *, max_file_bytes: int = MAX_FILE_BYTES) -> StagedRepo:
    """Copy `source` into a fresh `<tmp>/repo`, normalized as described in the module docstring."""
    source = Path(source)
    if not source.is_dir():
        raise FileNotFoundError(f"instance directory not found: {source}")

    candidates, withheld = _collect(source)
    if parent is not None:
        Path(parent).mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="stage-", dir=parent))
    root = workspace / "repo"
    root.mkdir(mode=DIR_MODE)

    copied: list[str] = []
    for rel in sorted(candidates):
        src = source / rel
        size = src.stat().st_size
        if size > max_file_bytes:
            withheld.append(WithheldFile(rel, size, "too_large"))
            continue
        data = src.read_bytes()
        if _is_binary(data):
            withheld.append(WithheldFile(rel, size, "binary"))
            continue
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
        with dest.open("xb") as handle:
            handle.write(data)
        copied.append(rel)

    _normalize_metadata(root)
    return StagedRepo(root=root, files=tuple(copied), withheld=tuple(sorted(withheld, key=lambda w: w.path)))


def _collect(source: Path) -> tuple[list[str], list[WithheldFile]]:
    files: list[str] = []
    withheld: list[WithheldFile] = []
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        here = Path(dirpath)
        kept_dirs = []
        for name in dirnames:
            if name in EXCLUDED_DIRS:
                continue
            if (here / name).is_symlink():
                withheld.append(WithheldFile(_rel(here / name, source), 0, "symlink"))
                continue
            kept_dirs.append(name)
        dirnames[:] = kept_dirs
        for name in filenames:
            path = here / name
            rel = _rel(path, source)
            if path.suffix in EXCLUDED_SUFFIXES:
                continue
            if path.is_symlink():
                withheld.append(WithheldFile(rel, 0, "symlink"))
            elif not path.is_file():
                withheld.append(WithheldFile(rel, 0, "special"))
            else:
                files.append(rel)
    return files, withheld


def _rel(path: Path, source: Path) -> str:
    return PurePosixPath(path.relative_to(source).as_posix()).as_posix()


def _is_binary(data: bytes) -> bool:
    head = data[:_BINARY_SNIFF_BYTES]
    if b"\x00" in head:  # noqa: PLR2004 - a NUL byte: binary
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _normalize_metadata(root: Path) -> None:
    # Bottom-up, so that setting a file's times does not bump its directory's mtime afterwards.
    for dirpath, _dirnames, filenames in os.walk(root, topdown=False):
        for name in filenames:
            path = os.path.join(dirpath, name)
            os.chmod(path, FILE_MODE)
            os.utime(path, (FIXED_MTIME, FIXED_MTIME))
        os.chmod(dirpath, DIR_MODE)
        os.utime(dirpath, (FIXED_MTIME, FIXED_MTIME))
