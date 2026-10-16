"""The prediction schema ships in the wheel but nothing reads it at runtime, so
it can drift away from the scorer unnoticed. These checks pin it, with no
dependency beyond the standard library."""

from __future__ import annotations

import json
import re
from pathlib import Path


def _schema(root: Path) -> dict:
    return json.loads((root / "schemas/prediction.schema.json").read_text(encoding="utf-8"))


def test_instance_pattern_matches_real_identifiers(root: Path, pairs: list[dict]) -> None:
    pattern = re.compile(_schema(root)["properties"]["instance_id"]["pattern"])
    for pair in pairs:
        assert pattern.match(pair["baseline_instance_id"])
        assert pattern.match(pair["mutant_instance_id"])
        if pair.get("placebo_instance_id"):
            assert pattern.match(pair["placebo_instance_id"])


def test_finding_properties_match_the_scorer(root: Path) -> None:
    from haystack_component_vulnerability_benchmark.score import _normalize_finding

    properties = set(_schema(root)["properties"]["findings"]["items"]["properties"])
    assert properties == {"path", "line_start", "line_end", "cwe", "title", "confidence"}
    normalized = _normalize_finding(
        {"path": "src/a.py", "line_start": 1, "line_end": 2, "cwe": "89"}
    )
    assert set(normalized) <= properties


def test_required_keys_are_what_the_scorer_demands(root: Path) -> None:
    schema = _schema(root)
    assert set(schema["required"]) == {"instance_id", "findings"}
    assert set(schema["properties"]["findings"]["items"]["required"]) == {
        "path",
        "line_start",
        "cwe",
    }
