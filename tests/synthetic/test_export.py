# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json

import pytest
from pydantic import ValidationError

from security_agent.synthetic.cwe import normalize_cwe
from security_agent.synthetic.export import benchmark_path, write_predictions
from security_agent.synthetic.schema import Finding, ScanReport, ScanResult


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("CWE-89", "CWE-89"),
        ("cwe_89", "CWE-89"),
        ("CWE 918", "CWE-918"),
        ("89", "CWE-89"),
        (89, "CWE-89"),
        ("CWE-89: SQL injection at line 42", "CWE-89"),
        ("SSRF", "CWE-918"),
        ("Path Traversal", "CWE-22"),
        ("CWE-0", None),
        ("", None),
        (None, None),
        (True, None),
        ("N/A", None),
        ("injection", None),
    ],
)
def test_normalize_cwe(raw, expected):
    assert normalize_cwe(raw) == expected


def test_finding_validation():
    with pytest.raises(ValidationError):
        Finding(path="a.py", line_start=5, line_end=4, cwe="CWE-89", title="x")
    with pytest.raises(ValidationError):
        Finding(path="a.py", line_start=1, line_end=1, cwe="CWE-89: SQLi", title="x")
    with pytest.raises(ValidationError):
        Finding(path="a.py", line_start=0, line_end=1, cwe="CWE-89", title="x")


def test_report_verdicts():
    finding = Finding(path="a.py", line_start=1, line_end=1, cwe="CWE-89", title="x")
    assert ScanReport.from_result("i1", "s", ScanResult(findings=[finding])).verdict == "vulnerable"
    assert ScanReport.from_result("i1", "s", ScanResult()).verdict == "no_findings"
    incomplete = ScanReport.from_result("i1", "s", ScanResult(findings=[finding], complete=False))
    assert (incomplete.status, incomplete.verdict) == ("incomplete", "incomplete")
    assert ScanReport.failed("i1", "s", "boom").verdict == "incomplete"


def test_findings_ranked_by_confidence():
    low = Finding(path="a.py", line_start=1, line_end=1, cwe="CWE-89", title="low", confidence=10)
    none = Finding(path="a.py", line_start=2, line_end=2, cwe="CWE-89", title="none")
    high = Finding(path="a.py", line_start=3, line_end=3, cwe="CWE-89", title="high", confidence=90)
    report = ScanReport.from_result("i1", "s", ScanResult(findings=[low, none, high]))
    assert [f.title for f in report.findings] == ["high", "low", "none"]


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("/repo/src/a.py", "src/a.py"),
        ("./src/a.py", "src/a.py"),
        ("/src/a.py", "src/a.py"),
        ("src\\a.py", "src/a.py"),
        ("src/../a.py", None),
        ("", None),
    ],
)
def test_benchmark_path(raw, expected):
    assert benchmark_path(raw) == expected


def test_write_predictions_one_line_per_expected_instance(tmp_path):
    good = Finding(path="/repo/src/a.py", line_start=3, line_end=4, cwe="CWE-89", title="sqli", confidence=80)
    escaping = Finding(path="../x.py", line_start=1, line_end=1, cwe="CWE-89", title="bad")
    reports = [
        ScanReport.from_result("i1", "s", ScanResult(findings=[good, escaping])),
        ScanReport.failed("i2", "s", "timeout"),
        ScanReport.from_result("unexpected", "s", ScanResult()),
    ]
    out = tmp_path / "predictions.jsonl"
    stats = write_predictions(reports, ["i1", "i2", "i3"], out)

    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert [r["instance_id"] for r in rows] == ["i1", "i2", "i3"]
    assert rows[0]["findings"] == [
        {"path": "src/a.py", "line_start": 3, "line_end": 4, "cwe": "CWE-89", "title": "sqli"}
    ]
    assert rows[1]["findings"] == [] and rows[2]["findings"] == []
    assert stats.dropped == {"bad_path": 1}
    assert stats.incomplete == ["i2"]
    assert stats.missing == ["i3"]
    assert stats.instances == 3 and stats.findings == 1
