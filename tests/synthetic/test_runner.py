# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

import pytest
from helpers import FakeBenchmark

from security_agent.synthetic.bench.runner import RunError, load_journal, run
from security_agent.synthetic.scan import EmptyScanner
from security_agent.synthetic.schema import Finding, ScanResult


class RecordingScanner:
    name = "recording"

    def __init__(self, fail_on: set[str] = frozenset()):
        self.fail_on = fail_on
        self.roots: list[Path] = []
        self.calls = 0

    def describe(self):
        return {"name": self.name}

    def scan(self, repo):
        self.calls += 1
        self.roots.append(repo.root)
        content = (repo.root / "src/app.py").read_text()
        if any(token in content for token in self.fail_on):
            raise RuntimeError("boom")
        finding = Finding(path="src/app.py", line_start=1, line_end=1, cwe="CWE-798", title="constant", confidence=60)
        return ScanResult(findings=[finding], record={"seen": content})


def test_run_journals_exports_and_isolates_instance_ids(tmp_path):
    bench = FakeBenchmark(tmp_path)
    scanner = RecordingScanner(fail_on={"VALUE = 2"})
    summary = run(bench, scanner, tmp_path / "run", concurrency=2, log=lambda *_: None)

    assert (summary.selected, summary.complete, summary.incomplete) == (4, 3, 1)
    rows = [json.loads(line) for line in (tmp_path / "run/predictions.jsonl").read_text().splitlines()]
    assert [r["instance_id"] for r in rows] == [i.instance_id for i in bench.instances()]
    assert sum(len(r["findings"]) for r in rows) == 3
    assert summary.export.incomplete == ["instance-00000000000000000002"]
    assert len(list((tmp_path / "run/records").glob("*.json"))) == 3

    # The scanner never sees the instance id: not in the staged path, and staging is cleaned up.
    for root in scanner.roots:
        assert "instance-" not in str(root)
        assert not root.exists()


def test_resume_skips_complete_and_retries_incomplete(tmp_path):
    bench = FakeBenchmark(tmp_path)
    run(bench, RecordingScanner(fail_on={"VALUE = 2"}), tmp_path / "run", log=lambda *_: None)
    second = RecordingScanner()
    summary = run(bench, second, tmp_path / "run", log=lambda *_: None)
    assert second.calls == 1
    assert (summary.skipped, summary.complete, summary.incomplete) == (3, 4, 0)
    journal = load_journal(tmp_path / "run/reports.jsonl")
    assert all(r.status == "complete" for r in journal.values())


def test_subset_and_mismatch(tmp_path):
    bench = FakeBenchmark(tmp_path)
    summary = run(bench, EmptyScanner(), tmp_path / "run", limit=2, log=lambda *_: None)
    assert summary.subset and summary.selected == 2
    assert len((tmp_path / "run/predictions.jsonl").read_text().splitlines()) == 2
    with pytest.raises(RunError):
        run(bench, RecordingScanner(), tmp_path / "run", limit=2, log=lambda *_: None)
    with pytest.raises(RunError):
        run(bench, EmptyScanner(), tmp_path / "run", limit=3, log=lambda *_: None)


def test_keep_staging_writes_index(tmp_path):
    bench = FakeBenchmark(tmp_path, n=2)
    run(bench, EmptyScanner(), tmp_path / "run", keep_staging=True, log=lambda *_: None)
    index = [json.loads(line) for line in (tmp_path / "run/staging/index.jsonl").read_text().splitlines()]
    assert len(index) == 2 and all(Path(row["root"], "src/app.py").is_file() for row in index)
