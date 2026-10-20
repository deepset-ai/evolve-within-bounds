# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""Shared test fixtures: a model config for the fake server, tiny repositories and benchmarks."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import yaml

from security_agent.synthetic.bench.adapters import Benchmark
from security_agent.synthetic.config import REPO_ROOT

SEED = REPO_ROOT / "agents" / "synthetic" / "seed"
LOOPED = REPO_ROOT / "agents" / "synthetic" / "looped"

STORE = (
    "from .util import quote\n"  # 1
    "\n"  # 2
    "class Store:\n"  # 3
    "    def __init__(self, table: str):\n"  # 4
    "        self.table = table\n"  # 5
    "\n"  # 6
    "    def filter(self, field, value):\n"  # 7
    "        name = quote(field)\n"  # 8
    "        sql = f\"SELECT * FROM {self.table} WHERE {name} = '{value}'\"\n"  # 9
    "        return self.conn.execute(sql)\n"  # 10
)
UTIL = "def quote(name):\n    return '\"' + name + '\"'\n"


def model(url: str) -> dict:
    return {"api_base_url": url, "model": "qwen", "timeout_s": 10, "max_retries": 0, "concurrency": 4}


def candidate(
    tmp_path: Path, edit=None, code: dict[str, str] | None = None, name: str = "cand", base: Path = SEED
) -> Path:
    """A copy of `base`, with `edit(data)` applied to its pipeline.yaml and `code` written to tools/."""
    dest = tmp_path / name
    shutil.copytree(base, dest)
    if edit:
        data = yaml.safe_load((dest / "pipeline.yaml").read_text())
        edit(data)
        (dest / "pipeline.yaml").write_text(yaml.safe_dump(data, sort_keys=False))
    for rel, text in (code or {}).items():
        (dest / "tools").mkdir(exist_ok=True)
        (dest / "tools" / rel).write_text(text)
    return dest


class FakeBenchmark(Benchmark):
    """`n` repositories with one file each, or with `files` each."""

    def __init__(self, tmp_path: Path, n: int = 4, files: dict[str, str] | None = None):
        root = tmp_path / "bench"
        (root / "data").mkdir(parents=True)
        (root / "data/pairs.jsonl").write_text("")
        super().__init__("fake", root, "fake_module", tmp_path / "work")
        self.materialized = tmp_path / "materialized"
        rows = []
        for k in range(n):
            instance_id = f"instance-{k:020d}"
            inst = self.materialized / instance_id
            for rel, content in (files or {"src/app.py": f"VALUE = {k}\n"}).items():
                (inst / rel).parent.mkdir(parents=True, exist_ok=True)
                (inst / rel).write_text(content)
            rows.append(json.dumps({"instance_id": instance_id, "path": str(inst)}))
        (self.materialized / "scan_manifest.jsonl").write_text("\n".join(rows) + "\n")

    @property
    def manifest_path(self) -> Path:
        return self.materialized / "scan_manifest.jsonl"


def pair_files(tmp_path: Path) -> dict[str, Path]:
    roots = {}
    for member, line in (
        ("mutant", "    return requests.get(url)\n"),
        ("baseline", "    return requests.get(check(url))\n"),
    ):
        root = tmp_path / member
        (root / "src").mkdir(parents=True)
        (root / "src/fetch.py").write_text("import requests\n\n\ndef fetch(url):\n" + line + "\n" * 30)
        roots[member] = root
    return roots


PAIR = {
    "pair_id": "pair-x",
    "repository": "repo-x",
    "cwe": "CWE-918",
    "title": "URL fetched unchecked",
    "targets": [
        {
            "path": "src/fetch.py",
            "role": "sink",
            "mutant_line_start": 5,
            "mutant_line_end": 5,
            "baseline_line_start": 5,
            "baseline_line_end": 5,
        }
    ],
}


class _Instance:
    def __init__(self, instance_id, path):
        self.instance_id, self.path = instance_id, path


class OnePairBench:
    """PAIR as a benchmark: m1 is its vulnerable repository, b1 its safe twin."""

    def __init__(self, tmp_path: Path):
        roots = pair_files(tmp_path)
        self.root = tmp_path / "bench"
        (self.root / "data").mkdir(parents=True)
        (self.root / "data" / "pairs.jsonl").write_text(
            json.dumps({**PAIR, "mutant_instance_id": "m1", "baseline_instance_id": "b1"}) + "\n"
        )
        self.roots = {"m1": roots["mutant"], "b1": roots["baseline"]}

    def instances(self):
        return [_Instance(iid, path) for iid, path in self.roots.items()]


class PairBenchmark(Benchmark):
    """Two pairs on STORE: the fake agent flags line 9 (the SELECT). pair-a's planted line is 9, pair-b's is 5."""

    SAFE = STORE.replace("SELECT * FROM", "QUERY_ALL FROM")

    def __init__(self, tmp_path: Path):
        root = tmp_path / "bench"
        (root / "data").mkdir(parents=True)
        pairs, key, manifest = [], [], []
        for pair_id, line in (("pair-a", 9), ("pair-b", 5)):
            ids = {m: f"instance-{pair_id}-{m}".ljust(29, "0") for m in ("mutant", "baseline")}
            for member, iid in ids.items():
                inst = tmp_path / "materialized" / iid
                (inst / "src/pkg").mkdir(parents=True)
                (inst / "src/pkg/store.py").write_text(STORE if member == "mutant" else self.SAFE)
                (inst / "src/pkg/util.py").write_text(UTIL)
                key.append({"instance_id": iid, "member": member, "pair_id": pair_id})
                manifest.append({"instance_id": iid, "path": str(inst)})
            pairs.append(
                {
                    "pair_id": pair_id,
                    "pair_class": "planted",
                    "repository": "repo",
                    "cwe": "CWE-89",
                    "title": f"title {pair_id}",
                    "mutant_instance_id": ids["mutant"],
                    "baseline_instance_id": ids["baseline"],
                    "targets": [
                        {
                            "path": "src/pkg/store.py",
                            "role": "sink",
                            "mutant_line_start": line,
                            "mutant_line_end": line,
                            "baseline_line_start": line,
                            "baseline_line_end": line,
                        }
                    ],
                }
            )
        (root / "data/pairs.jsonl").write_text("".join(json.dumps(p) + "\n" for p in pairs))
        (tmp_path / "answer_key.json").write_text(json.dumps({"instances": key}))
        (tmp_path / "manifest.jsonl").write_text("".join(json.dumps(m) + "\n" for m in manifest))
        super().__init__("pairbench", root, "none", tmp_path / "work")
        self.tmp = tmp_path
        self.pairs = pairs

    @property
    def manifest_path(self):
        return self.tmp / "manifest.jsonl"

    @property
    def answer_key_path(self):
        return self.tmp / "answer_key.json"

    def prepare(self):
        pass

    def score(self, predictions, output, *, allow_missing=False, line_tolerance=2):
        found = {
            json.loads(line)["instance_id"]: json.loads(line)["findings"]
            for line in predictions.read_text().splitlines()
            if line.strip()
        }
        rows = []
        for p in self.pairs:
            t = p["targets"][0]

            def near(iid, lo, hi, t=t):
                return [
                    f
                    for f in found.get(iid, [])
                    if f["path"] == t["path"]
                    and f["line_start"] <= hi + line_tolerance
                    and f["line_end"] >= lo - line_tolerance
                ]

            mut = near(p["mutant_instance_id"], t["mutant_line_start"], t["mutant_line_end"])
            base = near(p["baseline_instance_id"], t["baseline_line_start"], t["baseline_line_end"])
            detected, alarm = any(f["cwe"] == p["cwe"] for f in mut), any(f["cwe"] == p["cwe"] for f in base)
            rows.append(
                {
                    "pair_id": p["pair_id"],
                    "pair_class": "planted",
                    "cwe": p["cwe"],
                    "mutant_detected": detected,
                    "mutant_localized": bool(mut),
                    "baseline_mapped_alarm": alarm,
                    "baseline_mapped_localization_alarm": bool(base),
                    "pair_correct": detected and not alarm,
                    "pair_localized_correct": bool(mut) and not base,
                }
            )
        report = {"pair_results": rows}
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report))
        return report
