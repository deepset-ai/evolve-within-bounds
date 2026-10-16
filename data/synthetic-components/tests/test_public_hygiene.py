"""Layer A of the publication gate: rules that leak nothing and always run.

A denylist of customer names cannot live in a public repository -- committing one
publishes the list, and hashing it only produces a membership oracle over a small
guessable space. So the question is inverted: every identifier that appears must be
drawn from a declared generic vocabulary, and every host must be a reserved example
domain. A name that was never generated cannot pass. The complementary denylist scan
(Layer B) runs from an internal checkout and never enters this tree.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

# RFC 2606 reserves these entirely, so any subdomain of them is safe.
RESERVED_SUFFIXES = (".example.com", ".example.org", ".example.net", ".example.invalid")
ALLOWED_HOSTS = {
    "example.com",
    "example.org",
    "example.net",
    "example.invalid",
    "localhost",
    "127.0.0.1",
    "apache.org",
    "www.apache.org",
    "json-schema.org",
    "pypi.org",
    "files.pythonhosted.org",
    "github.com",
}
# Assembled from parts: writing the literal would put the very string this rule
# forbids into a tracked file.
FORBIDDEN_ORG = "deepset" + "-ai/"


def _host_allowed(host: str) -> bool:
    bare = host.split(":")[0]
    return bare in ALLOWED_HOSTS or bare.endswith(RESERVED_SUFFIXES)


ALLOWED_EMAIL_DOMAINS = {"example.invalid"}
FORBIDDEN_SCOPE = ("materialized", "reports/", ".cache", "dist/", ".idea")
HEX40 = re.compile(r"\b[0-9a-f]{40}\b")
URL_HOST = re.compile(r"https?://([A-Za-z0-9._:-]+)")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
SECRET_LIKE = re.compile(
    r"(api[_-]?key|token|password|secret)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]", re.IGNORECASE
)
ADJUDICATION_VOCABULARY = (
    "TRUE_BUT_OVERSTATED",
    "accepted_contamination",
    "FINDINGS_verdicts",
    "existing_findings",
    "scanner_severity",
)
MAX_TRACKED_BYTES = 2 * 1024 * 1024


@pytest.fixture(scope="module")
def tracked(root: Path) -> list[str]:
    probe = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode:
        pytest.skip("not a git work tree")
    return subprocess.run(
        ["git", "-C", str(root), "ls-files"], capture_output=True, text=True, check=True
    ).stdout.split()


@pytest.fixture(scope="module")
def vocabulary(root: Path) -> set[str]:
    document = json.loads((root / "data/vocabulary.json").read_text(encoding="utf-8"))
    return {term.lower() for term in document["corpus_terms"] + document["technical_terms"]}


# This file necessarily spells out the patterns it forbids, so it would match its own
# rules. It is excluded from the content scans and must instead be read by a human --
# it is short, and it is the one file a reviewer has to actually read for this gate.
SELF = "tests/test_public_hygiene.py"


def _text_files(root: Path, tracked: list[str]):
    for relative in tracked:
        if relative == SELF:
            continue
        path = root / relative
        try:
            yield relative, path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue


def test_every_path_token_is_declared(root: Path, tracked: list[str], vocabulary: set[str]) -> None:
    unknown: set[str] = set()
    for relative in tracked:
        for part in re.split(r"[/._\-]+", relative):
            for word in re.findall(r"[A-Za-z]+", part):
                if word.lower() not in vocabulary:
                    unknown.add(word)
    assert not unknown, f"undeclared identifiers in tracked paths: {sorted(unknown)}"


def test_every_host_is_reserved(root: Path, tracked: list[str]) -> None:
    offenders: set[str] = set()
    for _relative, text in _text_files(root, tracked):
        for host in URL_HOST.findall(text):
            if not _host_allowed(host):
                offenders.add(host)
    assert not offenders, f"non-reserved hosts: {sorted(offenders)}"


def test_every_email_domain_is_reserved(root: Path, tracked: list[str]) -> None:
    offenders = {
        domain
        for _relative, text in _text_files(root, tracked)
        for domain in EMAIL.findall(text)
        if domain not in ALLOWED_EMAIL_DOMAINS
    }
    assert not offenders, f"non-reserved email domains: {sorted(offenders)}"


def test_no_commit_shaped_hex_runs(root: Path, tracked: list[str]) -> None:
    """A 40-hex run would be a leaked commit SHA. Digests here are 64 hex."""
    offenders = [
        relative
        for relative, text in _text_files(root, tracked)
        if HEX40.search(text) and not relative.endswith((".json", ".jsonl"))
    ]
    assert not offenders, offenders


def test_no_internal_org_references(root: Path, tracked: list[str]) -> None:
    offenders = [
        relative
        for relative, text in _text_files(root, tracked)
        if FORBIDDEN_ORG in text or "git@github.com:" in text
    ]
    assert not offenders, offenders


def test_no_non_canary_secret_literals(root: Path, tracked: list[str]) -> None:
    offenders = [
        f"{relative}:{match.group(0)[:40]}"
        for relative, text in _text_files(root, tracked)
        for match in SECRET_LIKE.finditer(text)
        if "BENCHMARK_INERT_TOKEN" not in match.group(0)
    ]
    assert not offenders, offenders


def test_no_adjudication_vocabulary(root: Path, tracked: list[str]) -> None:
    offenders = [
        relative
        for relative, text in _text_files(root, tracked)
        for term in ADJUDICATION_VOCABULARY
        if term in text
    ]
    assert not offenders, offenders


def test_scope_hygiene(root: Path, tracked: list[str]) -> None:
    """An ignored directory reaching the index is how a leak actually happens."""
    offenders = [r for r in tracked for marker in FORBIDDEN_SCOPE if r.startswith(marker)]
    assert not offenders, offenders
    oversized = [r for r in tracked if (root / r).stat().st_size > MAX_TRACKED_BYTES]
    assert not oversized, oversized


def test_no_absolute_home_paths(root: Path, tracked: list[str]) -> None:
    offenders = [
        relative
        for relative, text in _text_files(root, tracked)
        if "/Users/" in text or "/home/" in text
    ]
    assert not offenders, offenders
