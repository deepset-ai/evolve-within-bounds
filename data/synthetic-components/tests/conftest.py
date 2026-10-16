from __future__ import annotations

import json
from pathlib import Path

import pytest

from haystack_component_vulnerability_benchmark.catalog import default_root, load_pairs


@pytest.fixture(scope="session")
def root() -> Path:
    return default_root()


@pytest.fixture(scope="session")
def pairs(root: Path) -> list[dict]:
    return load_pairs(root)


@pytest.fixture(scope="session")
def triplet(pairs: list[dict]) -> dict:
    """A pair that carries a placebo control."""
    return next(pair for pair in pairs if pair.get("placebo_instance_id"))


@pytest.fixture(scope="session")
def multi_file_pair(pairs: list[dict]) -> dict:
    return next(pair for pair in pairs if len(pair["targets"]) > 1)


@pytest.fixture(scope="session")
def single_file_pair(pairs: list[dict]) -> dict:
    return next(
        pair for pair in pairs if len(pair["targets"]) == 1 and not pair.get("placebo_instance_id")
    )


UNRELATED_CWE = "CWE-306"


def _write_predictions(
    path: Path,
    pairs: list[dict],
    *,
    detect: bool = True,
    baseline_alarm: bool = False,
    placebo_alarm: bool = False,
    cwe_override: str | None = None,
) -> None:
    """Emit a complete prediction file, one row per instance."""
    from haystack_component_vulnerability_benchmark.catalog import primary_target

    rows: list[dict] = []
    for index, pair in enumerate(pairs):
        sink = primary_target(pair)
        cwe = cwe_override or pair["cwe"]

        def finding(entry: dict, member: str, cwe: str = cwe) -> dict:
            return {
                "path": entry["path"],
                "line_start": entry[f"{member}_line_start"],
                "line_end": entry[f"{member}_line_end"],
                "cwe": cwe,
            }

        rows.append(
            {
                "instance_id": pair["baseline_instance_id"],
                "findings": [finding(sink, "baseline")] if baseline_alarm and index == 0 else [],
            }
        )
        rows.append(
            {
                "instance_id": pair["mutant_instance_id"],
                "findings": [finding(sink, "mutant")] if detect else [],
            }
        )
        if pair.get("placebo_instance_id"):
            findings = (
                [finding(target, "mutant") for target in pair["placebo_targets"]]
                if placebo_alarm
                else []
            )
            rows.append({"instance_id": pair["placebo_instance_id"], "findings": findings})
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


@pytest.fixture(scope="session")
def write_predictions():
    return _write_predictions
