# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json
from collections import Counter, defaultdict
from pathlib import Path

import pytest

from security_agent.data import primevul

DATA = Path(__file__).resolve().parents[1] / "data" / "primevul"
NAMES = primevul.manifest_names(DATA)


def _rows(name):
    return primevul.read_manifest(DATA / "manifests" / f"{name}.manifest.jsonl")[1]


def test_record_matches_the_experiments_format():
    row = {"idx": 7, "func": "int f(void) { return 0; }", "target": 1, "cwe": ["CWE-787", "CWE-125"], "project": "p"}
    record = primevul.build_record(row, "primevul-train-3", "train")
    assert list(record) == ["id", "code", "lang", "gold_is_vulnerable", "gold_cwe", "pair_id", "split"]
    assert record == {
        "id": "7",
        "code": "int f(void) { return 0; }",
        "lang": "c",
        "gold_is_vulnerable": True,
        "gold_cwe": "CWE-787",
        "pair_id": "primevul-train-3",
        "split": "train",
    }
    patched = primevul.build_record({**row, "target": 0}, "primevul-train-3", "train")
    assert patched["gold_is_vulnerable"] is False and patched["gold_cwe"] is None


def test_every_benchmark_file_has_a_manifest():
    assert NAMES == [
        "primevul-dev400",
        "primevul-dev410",
        "primevul-loop",
        "primevul-smoke13",
        "primevul-val2",
        "primevul-val2b",
    ]


@pytest.mark.parametrize("name", NAMES)
def test_manifest_is_well_formed(name):
    header, rows = primevul.read_manifest(DATA / "manifests" / f"{name}.manifest.jsonl")
    spec = primevul.load_upstream_spec(DATA)
    assert header["source"] == {"repo_id": spec["repo_id"], "revision": spec["revision"]}
    assert header["records"] == len(rows) and header["pairs"] * 2 == len(rows)
    members = defaultdict(set)
    for row in rows:
        assert set(row) == {"id", "pair_id", "split", "upstream", "row", "code_sha256"}
        assert primevul.UPSTREAM_SPLIT[row["split"]] == row["upstream"]
        assert 0 <= row["row"] < spec["files"][row["upstream"]]["rows"] and len(row["code_sha256"]) == 64
        members[row["pair_id"]].add(row["id"])
    # every pair is a vulnerable function and its patched twin: two different functions
    assert set(Counter(row["pair_id"] for row in rows).values()) == {2}
    assert all(len(ids) == 2 for ids in members.values())


def test_loop_splits_are_disjoint():
    ids = defaultdict(set)
    for row in _rows("primevul-loop"):
        ids[row["split"]].add(row["id"])
    assert not ids["train"] & ids["val"] and not ids["train"] & ids["holdout"] and not ids["val"] & ids["holdout"]


def test_dev_set_is_disjoint_from_the_loops_train_and_val():
    loop = {row["id"] for row in _rows("primevul-loop") if row["split"] in ("train", "val")}
    assert not loop & {row["id"] for row in _rows("primevul-dev410")}


def test_dev400_and_smoke13_come_from_dev410():
    dev410 = _rows("primevul-dev410")
    assert _rows("primevul-dev400") == dev410[:800]
    assert all(row in dev410 for row in _rows("primevul-smoke13"))


def _fake_upstream(tmp_path):
    """A two-pair upstream in the paired layout, with an `upstream.json` pinning it."""
    rows = [
        {"idx": 1, "func": "void a(char *p) { p[9] = 0; }", "target": 1, "cwe": ["CWE-787"], "project": "x"},
        {"idx": 2, "func": "void a(char *p, int n) { if (n > 9) p[9] = 0; }", "target": 0, "cwe": [], "project": "x"},
        {"idx": 3, "func": "int b(int *q) { return *q; }", "target": 1, "cwe": ["CWE-476"], "project": "y"},
        {"idx": 4, "func": "int b(int *q) { return q ? *q : 0; }", "target": 0, "cwe": [], "project": "y"},
    ]
    upstream_dir, data_dir = tmp_path / "upstream", tmp_path / "data"
    upstream_dir.mkdir()
    files = {}
    for split, content in {"train": rows, "validation": [], "test": []}.items():
        path = upstream_dir / f"{split}.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in content))
        files[split] = {"path": path.name, "rows": len(content), "sha256": primevul.sha256_file(path)}
    data_dir.mkdir()
    spec = {"repo_id": "example/PrimeVul", "revision": "0" * 40, "files": files}
    (data_dir / "upstream.json").write_text(json.dumps(spec))
    original = tmp_path / "bench.jsonl"
    records = [primevul.build_record(row, f"bench-{i // 2}", "train") for i, row in enumerate(rows)]
    original.write_text("".join(json.dumps(record) + "\n" for record in records[2:] + records[:2]))
    return upstream_dir, data_dir, spec, original


def test_build_rebuilds_a_file_byte_for_byte(tmp_path):
    upstream_dir, data_dir, spec, original = _fake_upstream(tmp_path)
    upstream = primevul.read_upstream(primevul.fetch(data_dir, upstream_dir))
    manifest = primevul.make_manifest(original, upstream, spec)
    (data_dir / "manifests").mkdir()
    (data_dir / "manifests" / "bench.manifest.jsonl").write_text("".join(json.dumps(line) + "\n" for line in manifest))
    assert [line["row"] for line in manifest[1:]] == [2, 3, 0, 1]  # order is the file's, not upstream's

    built = primevul.build(data_dir, tmp_path / "out", upstream_dir=upstream_dir)
    assert built[0].read_bytes() == original.read_bytes()
    assert primevul.verify(data_dir, tmp_path / "out") == []


def test_build_refuses_a_changed_upstream(tmp_path):
    upstream_dir, data_dir, spec, original = _fake_upstream(tmp_path)
    upstream = primevul.read_upstream(primevul.fetch(data_dir, upstream_dir))
    manifest = primevul.make_manifest(original, upstream, spec)
    (data_dir / "manifests").mkdir()
    (data_dir / "manifests" / "bench.manifest.jsonl").write_text("".join(json.dumps(line) + "\n" for line in manifest))

    train = upstream_dir / "train.jsonl"
    train.write_text(train.read_text().replace("p[9] = 0", "p[8] = 0"))
    with pytest.raises(primevul.PrimeVulDataError, match="sha256"):
        primevul.fetch(data_dir, upstream_dir)

    upstream["train"][0]["func"] += " "  # a row that no longer matches its manifest hash
    with pytest.raises(primevul.PrimeVulDataError, match="is not record"):
        primevul.build_file("bench", data_dir, upstream, tmp_path / "out")
    assert not (tmp_path / "out" / "bench.jsonl").exists()


@pytest.mark.integration
def test_every_file_rebuilds_from_the_hub(tmp_path):
    primevul.build(DATA, tmp_path)
    assert primevul.verify(DATA, tmp_path) == []
