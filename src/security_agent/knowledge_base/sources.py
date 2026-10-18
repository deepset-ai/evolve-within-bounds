# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The two sources, read into chunks: the CWE weakness definitions and the SEI CERT C rules.

A chunk is a dict with `chunk_id` (deterministic: the document id, and the reference the sub-agent cites), `content`,
`title`, `source`, and the source's identifier fields. `mapping.chunk_to_document` turns it into a Haystack Document.

- **CWE** (`cwe`): one chunk per entry of `cwe_reference.json`, its name and short description from the MITRE CWE
  List. Nothing is downloaded.
- **CERT C** (`cert_c`): one chunk per rule of the SEI CERT C Coding Standard: the rule's title, the prose before its
  first code example, its risk assessment and the CWE ids it is tagged with. Downloaded from the SEI's repository
  (cmu-sei/secure-coding-standards) at a pinned commit, so a changed upstream cannot change the corpus. Only the C
  standard's rules are read, not its recommendations.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

CWE_REFERENCE = Path(__file__).resolve().parent / "cwe_reference.json"
# The paths recorded in each document's metadata, which the sub-agent can read. They are kept as the experiments had
# them.
CWE_SOURCE_PATH = "data/cwe_reference.json"

CERT_C_REPO = "cmu-sei/secure-coding-standards"
CERT_C_COMMIT = "4f0e12d65e9941713054ca16edba85ba838a0dab"
CERT_C_RULES_PREFIX = "content/4.sei-cert-c-coding-standard/03.rules/"
TREE_URL = "https://api.github.com/repos/{repo}/git/trees/{ref}?recursive=1"
RAW_URL = "https://raw.githubusercontent.com/{repo}/{ref}/{path}"
ALLOWED_HOSTS = ("api.github.com", "raw.githubusercontent.com")
MAX_TREE_BYTES = 20_000_000
MAX_RULE_BYTES = 2_000_000
# The normative part of a rule is its title and the prose before the first code example: retrieval should find the
# rule, not quote its examples.
MAX_CONTENT_CHARS = 2400

# Model revisions on the Hugging Face Hub, so the vectors stored at build time and those computed at query time come
# from the same weights. `Qdrant/bm25` has no revision to pin; the fastembed version fixes it.
MODEL_REVISIONS = {
    "BAAI/bge-small-en-v1.5": "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a",
    "cross-encoder/ms-marco-MiniLM-L-6-v2": "c5ee24cb16019beea0893ab7796b1df96625c6b8",
}

_RULE_FILE_RE = re.compile(r"/\d+\.([a-z]{3}\d{2}-c)\.md$")
_TITLE_RE = re.compile(r"^# +(?P<id>[A-Z]{3}\d{2}-C)\. +(?P<title>.+?)\s*$", re.MULTILINE)
_SECTION_RE = re.compile(r"^## ", re.MULTILINE)
_ANCHOR_RE = re.compile(r"<a id=\"[^\"]*\"></a>\s*")
_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)


def chunk_id(source: str, key: str) -> str:
    """The chunk's id: the first 16 hex digits of sha256(`source:key`)."""
    return hashlib.sha256(f"{source}:{key}".encode()).hexdigest()[:16]


def cwe_chunks(reference: Path = CWE_REFERENCE) -> list[dict[str, Any]]:
    """One chunk per CWE entry: `CWE-787: <name>. <description>`."""
    data = json.loads(reference.read_text(encoding="utf-8"))
    chunks = []
    for cwe_id, entry in data.items():
        if not isinstance(entry, dict):
            continue
        name = (entry.get("name") or "").strip()
        description = (entry.get("description") or "").strip()
        body = ". ".join(part for part in (name, description) if part)
        chunks.append(
            {
                "chunk_id": chunk_id("cwe", cwe_id),
                "content": f"{cwe_id}: {body}" if body else cwe_id,
                "title": f"{cwe_id}: {name}" if name else cwe_id,
                "source": "cwe",
                "cwe_id": cwe_id,
                "source_path": CWE_SOURCE_PATH,
            }
        )
    return chunks


def fetch(url: str, max_bytes: int, timeout: float = 60.0) -> bytes:
    """GET `url` from an allowed host, refusing a body over `max_bytes`."""
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError(f"refusing to fetch from {urlparse(url).hostname}")
    request = urllib.request.Request(url, headers={"User-Agent": "security-agent-knowledge-base"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - https, allowed hosts only
        if urlparse(response.geturl()).hostname not in ALLOWED_HOSTS:
            raise ValueError(f"redirected to {urlparse(response.geturl()).hostname}")
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError(f"{url} is larger than {max_bytes} bytes")
    return body


def _clean(markdown: str) -> str:
    """Prose only: no anchors, tables, code blocks or link targets; whitespace collapsed."""
    text = _ANCHOR_RE.sub("", markdown)
    text = re.sub(r"::code-block\{[^}]*\}\n```.*?```\n::", "", text, flags=re.DOTALL)
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("|"))
    text = _LINK_RE.sub(r"\1", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def parse_rule(markdown: str) -> dict[str, Any] | None:
    """A rule page's id, title, CWE tags, normative prose and risk assessment; None if the page is not a rule."""
    frontmatter = _FRONTMATTER_RE.match(markdown)
    tags = re.findall(r"^\s*-\s*(\S+)", frontmatter.group(1), re.MULTILINE) if frontmatter else []
    cwes = sorted({f"CWE-{t.split('-', 1)[1]}" for t in tags if t.lower().startswith("cwe-")}, key=lambda c: int(c[4:]))
    body = markdown[frontmatter.end() :] if frontmatter else markdown
    title = _TITLE_RE.search(body)
    if not title:
        return None
    after_title = body[title.end() :]
    first_section = _SECTION_RE.search(after_title)
    intro = after_title[: first_section.start()] if first_section else after_title
    risk = ""
    risk_match = re.search(r"^## +Risk Assessment\s*\n(.*?)(?=^## |\Z)", after_title, re.MULTILINE | re.DOTALL)
    if risk_match:
        risk = _clean(risk_match.group(1))[:600]
    return {
        "rule_id": title.group("id"),
        "title": title.group("title").strip(),
        "cwe_ids": cwes,
        "intro": _clean(intro),
        "risk": risk,
    }


def cert_c_pages(cache_dir: Path, ref: str = CERT_C_COMMIT) -> list[dict[str, str]]:
    """Every C rule page at `ref`, downloaded once into `cache_dir`."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    tree_file = cache_dir / f"tree-{ref}.json"
    if not tree_file.exists():
        tree_file.write_bytes(fetch(TREE_URL.format(repo=CERT_C_REPO, ref=ref), MAX_TREE_BYTES))
    tree = json.loads(tree_file.read_text(encoding="utf-8"))
    paths = sorted(
        entry["path"]
        for entry in tree.get("tree", [])
        if entry.get("type") == "blob"
        and entry["path"].startswith(CERT_C_RULES_PREFIX)
        and _RULE_FILE_RE.search(entry["path"])
    )
    pages = []
    for path in paths:
        page_file = cache_dir / ref / Path(path).name
        if not page_file.exists():
            page_file.parent.mkdir(parents=True, exist_ok=True)
            page_file.write_bytes(fetch(RAW_URL.format(repo=CERT_C_REPO, ref=ref, path=path), MAX_RULE_BYTES))
        pages.append(
            {
                "path": path,
                "markdown": page_file.read_text(encoding="utf-8"),
                "source_path": f"{CERT_C_REPO}@{ref[:12]}:{path}",
            }
        )
    return pages


def cert_c_chunks(pages: list[dict[str, str]]) -> list[dict[str, Any]]:
    """One chunk per rule page; pages without a rule heading are skipped."""
    chunks = []
    for page in pages:
        rule = parse_rule(page["markdown"])
        if rule is None:
            logger.warning("CERT C: %s has no rule heading; skipped", page["path"])
            continue
        heading = f"{rule['rule_id']}. {rule['title']}"
        parts = [heading, rule["intro"]]
        if rule["risk"]:
            parts.append("Risk assessment: " + rule["risk"])
        if rule["cwe_ids"]:
            parts.append("Related CWE: " + ", ".join(rule["cwe_ids"]))
        chunks.append(
            {
                "chunk_id": chunk_id("cert_c", rule["rule_id"]),
                "content": "\n\n".join(p for p in parts if p)[:MAX_CONTENT_CHARS],
                "title": heading,
                "source": "cert_c",
                "rule_id": rule["rule_id"],
                "cwe_ids": rule["cwe_ids"],
                "source_path": page.get("source_path", page["path"]),
            }
        )
    return chunks
