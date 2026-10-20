# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Scrubbing third-party knowledge-base text before it reaches a model.

Every document is third-party text, so a poisoned upstream entry is an injection vector. This is one layer of the
defence: role and boundary markers are neutralized and lengths capped. The others are the pinned upstream commit
(`sources`), the sub-agent holding no tools but retrieval, the untrusted-content frame around its answer (`render`),
and a sentence in both agents' system prompts saying that knowledge-base text is data.

Documents are scrubbed when they are written to Qdrant (`mapping.chunk_to_document`), because the sub-agent reaches
them through five different tools of the agent pack; the answer it writes is scrubbed again when it is rendered.

The marker patterns and `safe_surface` follow redamon (github.com/samugit83/redamon, MIT), see NOTICE.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from haystack.dataclasses import Document

# Per-document content cap: stops one poisoned (or merely huge) entry dominating the context.
KB_CONTENT_MAX_CHARS = 2000
# Per-metadata-value cap. The agent pack shows each result's metadata to the sub-agent, so a title is as good an
# injection carrier as the body.
KB_META_MAX_CHARS = 500
KB_LIST_MAX_ITEMS = 10

REPLACEMENT = "[role-marker stripped]"

# The frame `render` puts around the sub-agent's answer. Stripped from all text, so no document and no answer can
# forge a closing boundary.
FRAME_BEGIN = "[BEGIN UNTRUSTED KNOWLEDGE BASE RESULTS]"
FRAME_END = "[END UNTRUSTED KNOWLEDGE BASE RESULTS]"

_PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<\s*/?\s*system\s*>", re.IGNORECASE),
    re.compile(r"<\s*/?\s*user\s*>", re.IGNORECASE),
    re.compile(r"<\s*/?\s*assistant\s*>", re.IGNORECASE),
    re.compile(r"<\s*/?\s*kb_chunk\s*>", re.IGNORECASE),
    re.compile(r"<\s*/?\s*kb_content\s*>", re.IGNORECASE),
    re.compile(r"\[\s*INST\s*\]", re.IGNORECASE),
    re.compile(r"\[\s*/\s*INST\s*\]", re.IGNORECASE),
    re.compile(r"<\|\s*im_start\s*\|>", re.IGNORECASE),
    re.compile(r"<\|\s*im_end\s*\|>", re.IGNORECASE),
    re.compile(r"\[\s*BEGIN\s+UNTRUSTED\s+KNOWLEDGE\s+BASE\s+RESULTS\s*\]", re.IGNORECASE),
    re.compile(r"\[\s*END\s+UNTRUSTED\s+KNOWLEDGE\s+BASE\s+RESULTS\s*\]", re.IGNORECASE),
)


def sanitize(content: str, max_chars: int = KB_CONTENT_MAX_CHARS) -> str:
    """Neutralize role and boundary markers in untrusted text, and cap its length."""
    if not content:
        return ""
    for pattern in _PROMPT_INJECTION_PATTERNS:
        content = pattern.sub(REPLACEMENT, content)
    if len(content) > max_chars:
        content = content[:max_chars] + "... [truncated]"
    return content


def _sanitize_meta_value(value: Any) -> Any:
    """Scrub a metadata value, keeping its type so that filters still compare."""
    if isinstance(value, str):
        return sanitize(value, max_chars=KB_META_MAX_CHARS)
    if isinstance(value, list):
        return [_sanitize_meta_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_meta_value(item) for key, item in value.items()}
    return value


def sanitize_document(document: Document) -> Document:
    """A document with its content and metadata scrubbed; its id (the citation handle) unchanged."""
    return replace(
        document,
        content=sanitize(document.content or "") or None,
        meta={key: _sanitize_meta_value(value) for key, value in (document.meta or {}).items()},
    )


def safe_surface(value: Any, default: str = "") -> str:
    """
    Any knowledge-base field as display text, with every string scrubbed.

    Every knowledge-base value that reaches a model goes through this: interpolating `doc.meta["x"]` into an f-string
    directly would bypass the scrubbing.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, list | tuple):
        items = [v for v in value if v is not None and v != ""]
        if not items:
            return default
        rendered = ", ".join(sanitize(str(v)) for v in items[:KB_LIST_MAX_ITEMS])
        if len(items) > KB_LIST_MAX_ITEMS:
            rendered += f" (+{len(items) - KB_LIST_MAX_ITEMS} more)"
        return rendered
    return sanitize(str(value))
