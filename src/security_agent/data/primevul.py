# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The PrimeVul files the experiments used, rebuilt from the upstream mirror on the Hugging Face Hub.

This repository does not carry PrimeVul's code. It ships manifests instead: which upstream rows each benchmark file
holds, in which order, under which pair id and split, and a hash of every function to check against. `build`
downloads the pinned upstream files and writes the benchmark files byte for byte as the experiments read them.

    python -m security_agent.data.primevul build             # all files, into data/primevul/build/
    python -m security_agent.data.primevul verify            # re-hash what was built
"""

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

DATA_DIR = Path("data/primevul")
MANIFEST_VERSION = 1
# Our split names and the upstream `paired` split each one was drawn from.
UPSTREAM_SPLIT = {"train": "train", "val": "validation", "holdout": "test"}
# The upstream fields round fourteen's repository context reads (`*.meta.json`).
META_FIELDS = ("project", "project_url", "commit_id", "file_name")


class PrimeVulDataError(RuntimeError):
    """A downloaded or built file does not match what the manifests pin."""


def sha256_bytes(data: bytes) -> str:
    """
    Hex sha256 of `data`.

    :param data: The bytes to hash.
    :returns: The lowercase hex digest.
    """
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """
    Hex sha256 of a file's bytes, read in chunks.

    :param path: The file to hash.
    :returns: The lowercase hex digest.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_upstream_spec(data_dir: Path) -> dict[str, Any]:
    """
    Read `upstream.json`: the Hub repository, its pinned revision, and each paired file with its sha256.

    :param data_dir: The folder holding `upstream.json`, `manifests/` and `repository-context/`.
    :returns: The parsed specification.
    """
    return json.loads((data_dir / "upstream.json").read_text(encoding="utf-8"))


def fetch(data_dir: Path, upstream_dir: Path | None = None) -> dict[str, Path]:
    """
    Make the three upstream paired files available and check them against their pinned sha256.

    :param data_dir: The folder holding `upstream.json`.
    :param upstream_dir: A folder that already holds the upstream files. When None, they are downloaded at the pinned
        revision into the Hugging Face cache, which needs the `primevul` extra (`huggingface_hub`).
    :returns: The local path of each upstream split's file.
    :raises PrimeVulDataError: If a file is missing or its sha256 differs from the pinned one.
    """
    spec = load_upstream_spec(data_dir)
    paths: dict[str, Path] = {}
    for split, entry in spec["files"].items():
        if upstream_dir is not None:
            path = upstream_dir / entry["path"]
        else:
            from huggingface_hub import hf_hub_download  # only needed for downloading

            path = Path(
                hf_hub_download(
                    repo_id=spec["repo_id"], repo_type="dataset", filename=entry["path"], revision=spec["revision"]
                )
            )
        if not path.is_file():
            raise PrimeVulDataError(f"upstream file missing: {path}")
        actual = sha256_file(path)
        if actual != entry["sha256"]:
            raise PrimeVulDataError(f"{entry['path']}: sha256 {actual}, pinned {entry['sha256']}")
        paths[split] = path
    return paths


def read_upstream(paths: dict[str, Path]) -> dict[str, list[dict[str, Any]]]:
    """
    Parse each upstream split's JSONL file into its rows, in file order.

    :param paths: The local path of each upstream split's file, as returned by `fetch`.
    :returns: The rows of each upstream split.
    """
    return {
        split: [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        for split, path in paths.items()
    }


def build_record(row: dict[str, Any], pair_id: str, split: str) -> dict[str, Any]:
    """
    One benchmark record from one upstream row, field for field as the experiments' loader wrote it.

    :param row: An upstream PrimeVul row (`idx`, `func`, `target`, `cwe`, ...).
    :param pair_id: The record's pair id, from the manifest.
    :param split: The record's split (`train`, `val` or `holdout`), from the manifest.
    :returns: The record with the keys `id`, `code`, `lang`, `gold_is_vulnerable`, `gold_cwe`, `pair_id`, `split`.
    """
    cwe = row.get("cwe")
    if isinstance(cwe, list | tuple):  # PrimeVul ships `cwe` as a sequence
        cwe = cwe[0] if cwe else None
    is_vulnerable = bool(row.get("target"))
    return {
        "id": str(row.get("idx")),
        "code": row.get("func", ""),
        "lang": "c",
        "gold_is_vulnerable": is_vulnerable,
        "gold_cwe": cwe if is_vulnerable else None,
        "pair_id": pair_id,
        "split": split,
    }


def read_manifest(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Read a manifest: a header line, then one line per record.

    :param path: The manifest file.
    :returns: The header and the record rows.
    :raises PrimeVulDataError: If the file is not a manifest of a known version.
    """
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines or lines[0].get("manifest") != MANIFEST_VERSION:
        raise PrimeVulDataError(f"{path}: not a version {MANIFEST_VERSION} manifest")
    return lines[0], lines[1:]


def manifest_names(data_dir: Path) -> list[str]:
    """
    The benchmark files the manifests describe.

    :param data_dir: The folder holding `manifests/`.
    :returns: The file names without extension, sorted.
    """
    return sorted(
        path.name.removesuffix(".manifest.jsonl") for path in (data_dir / "manifests").glob("*.manifest.jsonl")
    )


def _write_checked(path: Path, data: bytes, expected_sha256: str) -> None:
    """Write `data` to `path` only if it hashes to `expected_sha256`; otherwise leave `path` untouched and raise."""
    actual = sha256_bytes(data)
    if actual != expected_sha256:
        raise PrimeVulDataError(f"{path.name}: rebuilt sha256 {actual}, manifest pins {expected_sha256}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".partial")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def build_file(name: str, data_dir: Path, upstream: dict[str, list[dict[str, Any]]], out_dir: Path) -> Path:
    """
    Rebuild one benchmark file from the upstream rows its manifest names, and its meta file if it has one.

    :param name: The benchmark file's name without extension, e.g. `primevul-loop`.
    :param data_dir: The folder holding `manifests/` and `repository-context/`.
    :param upstream: The upstream rows of each split, as returned by `read_upstream`.
    :param out_dir: Where the rebuilt files go.
    :returns: The path of the rebuilt benchmark file.
    :raises PrimeVulDataError: If a function's code or a whole file does not match the manifest.
    """
    header, rows = read_manifest(data_dir / "manifests" / f"{name}.manifest.jsonl")
    lines = []
    for entry in rows:
        row = upstream[entry["upstream"]][entry["row"]]
        if str(row.get("idx")) != entry["id"] or sha256_bytes(row.get("func", "").encode()) != entry["code_sha256"]:
            raise PrimeVulDataError(
                f"{name}: upstream {entry['upstream']} row {entry['row']} is not record {entry['id']}"
            )
        lines.append(json.dumps(build_record(row, entry["pair_id"], entry["split"])) + "\n")
    out = out_dir / f"{name}.jsonl"
    _write_checked(out, "".join(lines).encode(), header["sha256"])
    meta = header.get("meta")
    if meta:
        _build_meta(meta, {entry["id"] for entry in rows}, data_dir, upstream, out_dir)
    return out


def _build_meta(
    meta: dict[str, Any], ids: set[str], data_dir: Path, upstream: dict[str, list[dict[str, Any]]], out_dir: Path
) -> None:
    """Round fourteen's meta file: the upstream fields per function, plus `repo_url` where our search moved it."""
    entries = {
        str(row["idx"]): {key: row.get(key) for key in META_FIELDS}
        for row in upstream[meta["upstream"]]
        if str(row["idx"]) in ids
    }
    if meta.get("commit_repos"):
        found = json.loads((data_dir / meta["commit_repos"]).read_text(encoding="utf-8"))
        for entry in entries.values():
            if entry.get("commit_id") in found:
                entry["repo_url"] = found[entry["commit_id"]]
    _write_checked(out_dir / meta["file"], json.dumps(entries, indent=0).encode(), meta["sha256"])


def build(
    data_dir: Path, out_dir: Path, names: Sequence[str] | None = None, upstream_dir: Path | None = None
) -> list[Path]:
    """
    Rebuild benchmark files from the pinned upstream files.

    :param data_dir: The folder holding `upstream.json`, `manifests/` and `repository-context/`.
    :param out_dir: Where the rebuilt files go.
    :param names: The files to rebuild; all files with a manifest when None.
    :param upstream_dir: A folder that already holds the upstream files; downloaded when None.
    :returns: The paths of the rebuilt benchmark files.
    """
    upstream = read_upstream(fetch(data_dir, upstream_dir))
    return [build_file(name, data_dir, upstream, out_dir) for name in (names or manifest_names(data_dir))]


def verify(data_dir: Path, out_dir: Path, names: Sequence[str] | None = None) -> list[str]:
    """
    Re-hash rebuilt files against their manifests.

    :param data_dir: The folder holding `manifests/`.
    :param out_dir: Where the rebuilt files are.
    :param names: The files to check; all files with a manifest when None.
    :returns: One line per problem; empty when every file matches.
    """
    problems = []
    for name in names or manifest_names(data_dir):
        header, _ = read_manifest(data_dir / "manifests" / f"{name}.manifest.jsonl")
        expected = [(f"{name}.jsonl", header["sha256"])]
        if header.get("meta"):
            expected.append((header["meta"]["file"], header["meta"]["sha256"]))
        for file_name, sha256 in expected:
            path = out_dir / file_name
            if not path.is_file():
                problems.append(f"{file_name}: missing")
            elif sha256_file(path) != sha256:
                problems.append(f"{file_name}: sha256 differs from the manifest")
    return problems


def make_manifest(
    jsonl: Path, upstream: dict[str, list[dict[str, Any]]], spec: dict[str, Any], meta: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """
    The manifest of an existing benchmark file: where each record's row is upstream, and the file's sha256.

    Every record must match its upstream row exactly (code, label and CWE), so that `build` can reproduce the file.

    :param jsonl: The benchmark file, in the experiments' record format.
    :param upstream: The upstream rows of each split, as returned by `read_upstream`.
    :param spec: The upstream specification from `upstream.json`.
    :param meta: Optional meta-file recipe (`file`, `upstream`, `commit_repos`, `sha256`) to record in the header.
    :returns: The manifest's lines: the header, then one per record.
    :raises PrimeVulDataError: If a record has no matching upstream row.
    """
    index: dict[tuple[str, str], int] = {}
    for split, rows in upstream.items():
        for position, row in enumerate(rows):
            index.setdefault((split, str(row["idx"])), position)
    data = jsonl.read_bytes()
    lines: list[dict[str, Any]] = []
    for record in (json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()):
        split = UPSTREAM_SPLIT[record["split"]]
        found = index.get((split, record["id"]))
        if found is None:
            raise PrimeVulDataError(f"{jsonl.name}: record {record['id']} not in upstream {split}")
        if build_record(upstream[split][found], record["pair_id"], record["split"]) != record:
            raise PrimeVulDataError(f"{jsonl.name}: record {record['id']} differs from upstream {split} row {found}")
        lines.append(
            {
                "id": record["id"],
                "pair_id": record["pair_id"],
                "split": record["split"],
                "upstream": split,
                "row": found,
                "code_sha256": sha256_bytes(record["code"].encode()),
            }
        )
    header: dict[str, Any] = {
        "manifest": MANIFEST_VERSION,
        "name": jsonl.name.removesuffix(".jsonl"),
        "source": {"repo_id": spec["repo_id"], "revision": spec["revision"]},
        "records": len(lines),
        "pairs": len({line["pair_id"] for line in lines}),
        "sha256": sha256_bytes(data),
    }
    if meta:
        header["meta"] = meta
    return [header, *lines]


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    """
    Command-line entry point.

    :param argv: The arguments, without the program name; `sys.argv[1:]` when None.
    :returns: The exit code.
    """
    parser = argparse.ArgumentParser(
        prog="python -m security_agent.data.primevul",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--data-dir", type=Path, default=DATA_DIR, help="upstream.json, manifests/, repository-context/"
    )
    parser.add_argument("--upstream-dir", type=Path, help="already downloaded upstream files (skips the download)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("fetch", help="download the pinned upstream files and check their sha256")
    for command in ("build", "verify"):
        sub = commands.add_parser(command, help=f"{command} benchmark files (all when none are named)")
        sub.add_argument("names", nargs="*", help=f"e.g. primevul-loop; one of {', '.join(manifest_names(DATA_DIR))}")
        sub.add_argument("--out", type=Path, default=DATA_DIR / "build")
    make = commands.add_parser("manifest", help="maintainers: write the manifest of an existing benchmark file")
    make.add_argument("jsonl", type=Path)
    make.add_argument("--meta", type=Path, help="its round-14 meta file, to pin as well")
    make.add_argument("--meta-upstream", choices=sorted(set(UPSTREAM_SPLIT.values())), help="the meta file's split")
    make.add_argument("--commit-repos", help="the meta file's commit-repos mapping, relative to --data-dir")
    args = parser.parse_args(argv)

    try:
        if args.command == "fetch":
            for split, path in fetch(args.data_dir, args.upstream_dir).items():
                print(f"{split}: {path}")
        elif args.command == "build":
            for path in build(args.data_dir, args.out, args.names, args.upstream_dir):
                print(f"built {path}")
        elif args.command == "verify":
            problems = verify(args.data_dir, args.out, args.names)
            print("\n".join(problems) if problems else "every file matches its manifest")
            return 1 if problems else 0
        else:
            upstream = read_upstream(fetch(args.data_dir, args.upstream_dir))
            meta = None
            if args.meta:
                meta = {
                    "file": args.meta.name,
                    "upstream": args.meta_upstream,
                    "commit_repos": args.commit_repos,
                    "sha256": sha256_file(args.meta),
                }
            out = args.data_dir / "manifests" / f"{args.jsonl.name.removesuffix('.jsonl')}.manifest.jsonl"
            _write_jsonl(out, make_manifest(args.jsonl, upstream, load_upstream_spec(args.data_dir), meta))
            print(f"wrote {out}")
    except PrimeVulDataError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
