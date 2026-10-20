# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Chunk to Haystack `Document`.

- The document id is the chunk's own `chunk_id`, so a rebuild writes the same ids and the sub-agent's citations
  stay stable.
- The title goes in front of the content when the content does not already start with it, so both the dense and the
  BM25 vector see the identifiers in it.
- Metadata is a per-source whitelist of flat values (and lists of strings); a missing value is left out rather than
  stored as None.
- Content and metadata are scrubbed here (`sanitize.sanitize_document`), so what Qdrant holds is safe to hand to a
  model.
"""

from __future__ import annotations

import logging
from typing import Any

from haystack.dataclasses import Document

from security_agent.knowledge_base.sanitize import sanitize_document

logger = logging.getLogger(__name__)

_COMMON_KEYS: tuple[str, ...] = ("title", "source", "source_path")
_SOURCE_KEYS: dict[str, tuple[str, ...]] = {"cwe": ("cwe_id",), "cert_c": ("rule_id", "cwe_ids")}
_LIST_KEYS = frozenset({"cwe_ids"})
_LIST_MAX = 20


class ChunkMappingError(ValueError):
    """A chunk without an id, a source or any text."""


def _compose_content(chunk: dict[str, Any]) -> str:
    title = (chunk.get("title") or "").strip()
    body = (chunk.get("content") or "").strip()
    if not body:
        return title
    if not title or body.startswith(title):
        return body
    return f"{title}\n\n{body}"


def _coerce(key: str, value: Any) -> Any:
    """A chunk field as a metadata value, or None to leave it out."""
    if value is None or value == "":
        return None
    if key in _LIST_KEYS:
        if isinstance(value, str):
            items = [value]
        elif isinstance(value, list | tuple):
            items = [str(v) for v in value if v not in (None, "")]
        else:
            return None
        return list(dict.fromkeys(items))[:_LIST_MAX] or None
    if isinstance(value, str | int | float | bool):
        return value.strip() if isinstance(value, str) else value
    return str(value)


def chunk_to_document(chunk: dict[str, Any]) -> Document:
    """One chunk as a scrubbed `Document`."""
    cid, source = chunk.get("chunk_id"), chunk.get("source")
    if not cid or not source:
        raise ChunkMappingError(f"chunk without chunk_id or source: {sorted(chunk)!r}")
    content = _compose_content(chunk)
    if not content:
        raise ChunkMappingError(f"chunk {cid} ({source}) has no content or title")
    meta: dict[str, Any] = {}
    for key in _COMMON_KEYS + _SOURCE_KEYS.get(source, ()):
        coerced = _coerce(key, chunk.get(key))
        if coerced is not None:
            meta[key] = coerced
    meta["source"] = source
    return sanitize_document(Document(id=str(cid), content=content, meta=meta))


def documents_from_chunks(chunks: list[dict[str, Any]]) -> list[Document]:
    """The chunks as documents, unmappable ones dropped; for a repeated id, the last one wins."""
    by_id: dict[str, Document] = {}
    for chunk in chunks:
        try:
            doc = chunk_to_document(chunk)
        except ChunkMappingError as exc:
            logger.warning("Skipping a chunk: %s", exc)
            continue
        by_id[doc.id] = doc
    return list(by_id.values())
