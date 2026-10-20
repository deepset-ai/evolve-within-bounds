# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Benchmark adapters: where instances come from and how predictions are scored.

The benchmark packages are never imported or installed here. Each benchmark's own CLI runs as a
subprocess from its source checkout, using only the standard library. Its catalog, patches and answer
keys therefore never enter an environment the agent can reach.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from security_agent.synthetic.config import load_yaml, resolve


class BenchmarkError(RuntimeError):
    pass


@dataclass(frozen=True)
class Instance:
    instance_id: str
    path: Path


class Benchmark:
    """Base adapter: a benchmark root with `data/pairs.jsonl` and a `<module>.cli` with a `score` command."""

    def __init__(self, name: str, root: Path, module: str, work_dir: Path, src_dir: Path | None = None) -> None:
        self.name = name
        self.root = root
        self.module = module
        self.src_dir = src_dir or root / "src"
        self.work_dir = work_dir / name
        if not (root / "data/pairs.jsonl").is_file():
            raise BenchmarkError(f"{name}: no data/pairs.jsonl under {root}")

    @property
    def manifest_path(self) -> Path:
        """The materialized benchmark's manifest."""
        raise NotImplementedError

    def prepare(self) -> None:
        """Make sure a materialized manifest exists."""

    def instances(self) -> list[Instance]:
        """The benchmark's instances, from its manifest."""
        manifest = self.manifest_path
        if not manifest.is_file():
            raise BenchmarkError(
                f"{self.name}: manifest {manifest} missing; run `security-agent synthetic bench prepare`"
            )
        instances = []
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            path = self._instance_path(manifest.parent, Path(row["path"]))
            if not path.is_dir():
                raise BenchmarkError(f"{self.name}: instance directory {path} missing")
            instances.append(Instance(row["instance_id"], path))
        return instances

    def _instance_path(self, manifest_dir: Path, recorded: Path) -> Path:
        return recorded if recorded.is_absolute() else manifest_dir / recorded

    @property
    def answer_key_path(self) -> Path:
        """The answer key; never shown to a scanner."""
        raise NotImplementedError

    def pair_instances(self, pair_ids: list[str]) -> list[str]:
        """Instance ids of the given pairs (all members, placebos included). Harness-side only: reads the answer key."""
        key = json.loads(self.answer_key_path.read_text(encoding="utf-8"))["instances"]
        known = {row["pair_id"] for row in key}
        unknown = sorted(set(pair_ids) - known)
        if unknown:
            raise BenchmarkError(f"{self.name}: unknown pair ids: {', '.join(unknown)}")
        return [row["instance_id"] for row in key if row["pair_id"] in set(pair_ids)]

    def score(
        self, predictions: Path, output: Path, *, allow_missing: bool = False, line_tolerance: int = 2
    ) -> dict[str, Any]:
        """Score a predictions file with the benchmark's own scorer."""
        args = [
            "score",
            str(predictions.resolve()),
            "--output",
            str(output.resolve()),
            "--line-tolerance",
            str(line_tolerance),
        ]
        if allow_missing:
            args.append("--allow-missing")
        output.parent.mkdir(parents=True, exist_ok=True)
        self._cli(*args)
        return json.loads(output.read_text(encoding="utf-8"))

    def _cli(self, *args: str) -> subprocess.CompletedProcess:
        env = {**os.environ, "PYTHONPATH": str(self.src_dir)}
        command = [sys.executable, "-m", f"{self.module}.cli", "--root", str(self.root), *args]
        self.work_dir.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(command, cwd=self.work_dir, env=env, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise BenchmarkError(
                f"{self.name}: `{' '.join(args[:1])}` failed ({proc.returncode}):\n{proc.stdout[-2000:]}\n"
                f"{proc.stderr[-2000:]}"
            )
        return proc


class Hvbench(Benchmark):
    """The synthetic custom-component benchmark, materialized offline into the work dir with its answer key."""

    @property
    def manifest_path(self) -> Path:
        """The materialized benchmark's manifest."""
        return self.work_dir / "materialized" / "scan_manifest.jsonl"

    @property
    def answer_key_path(self) -> Path:
        """The answer key, next to the materialized repositories."""
        return self.work_dir / "answer_key.json"

    def prepare(self) -> None:
        """Materialize the benchmark, unless it is already."""
        if self.manifest_path.is_file():
            return
        self._cli(
            "materialize",
            "--output",
            str(self.work_dir / "materialized"),
            "--answer-key",
            str(self.work_dir / "answer_key.json"),
        )


def load_benchmark(name: str, config: dict[str, Any] | None = None) -> Benchmark:
    """A configured benchmark by name."""
    config = config or load_yaml("benchmarks.yaml")
    entries = config.get("benchmarks", {})
    if name not in entries:
        raise BenchmarkError(f"unknown benchmark '{name}'; configured: {', '.join(sorted(entries))}")
    entry = entries[name]
    work_dir = resolve(config.get("work_dir", "work/synthetic"))
    common = {"name": name, "root": resolve(entry["root"]), "module": entry["module"], "work_dir": work_dir}
    if name == "hvbench":
        return Hvbench(**common)
    raise BenchmarkError(f"no adapter for '{name}'")
