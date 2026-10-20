# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The agent's answer as a verdict.

The agent is asked for one JSON object (`VulnerabilityVerdict`). `parse_verdict` reads it from the answer: the whole
answer as that object, or else the object inside it (in a code fence, after some prose, or cut off by one character),
or else any JSON object with an `is_vulnerable` key. An answer with none of these is a parse error, and scores as wrong:
a model that does not give the format is a real result.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field, ValidationError


def normalize_cwe(raw: Any) -> str | None:
    """'787', 'cwe-787' and 'CWE 787' are 'CWE-787'; empty, None or no digits are None."""
    if raw is None:
        return None
    digits = "".join(ch for ch in str(raw) if ch.isdigit())
    return f"CWE-{digits}" if digits else None


class VulnerabilityVerdict(BaseModel):
    """A security-triage verdict for a single source-code function."""

    is_vulnerable: bool = Field(description="Whether the function contains a security vulnerability.")
    cwe: str | None = Field(description="CWE identifier like 'CWE-89'; null when not vulnerable.")
    vulnerable_lines: list[int] = Field(description="1-based line numbers; empty when not vulnerable.")
    rationale: str = Field(description="One or two sentence justification.")


def _failed(text: str | None) -> dict[str, Any]:
    return {
        "is_vulnerable": None,
        "cwe": None,
        "vulnerable_lines": [],
        "rationale": "",
        "parse_error": True,
        "raw": (text or "")[:500],
    }


def parse_strict(text: str) -> dict[str, Any]:
    """The whole text as a `VulnerabilityVerdict`, normalized; a parse error otherwise."""
    try:
        verdict = VulnerabilityVerdict.model_validate_json(text or "")
    except ValidationError:
        return _failed(text)
    return {
        "is_vulnerable": verdict.is_vulnerable,
        "cwe": normalize_cwe(verdict.cwe),
        "vulnerable_lines": verdict.vulnerable_lines,
        "rationale": verdict.rationale.strip(),
        "parse_error": False,
    }


def _close_truncated_object(text: str) -> str | None:
    """
    A verdict cut off after its last value gets its closing brace back, if every key it needs is there.

    Seen with llama.cpp: the reply ends exactly one character early. A text missing a key is not repaired.
    """
    if not text.startswith("{") or text.endswith("}") or '"is_vulnerable"' not in text or '"rationale"' not in text:
        return None
    for suffix in ("}", '"}', "]}", '"]}'):
        candidate = text + suffix
        try:
            json.loads(candidate)
        except json.JSONDecodeError:
            continue
        return candidate
    return None


def _balanced_objects(text: str) -> list[str]:
    """Every top-level `{...}` span, with braces inside strings ignored."""
    spans: list[str] = []
    depth, start, in_string, escaped = 0, None, False, False
    for i, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                spans.append(text[start : i + 1])
    return spans


def extract_json_object(text: str) -> str | None:
    """
    The verdict object in a free-text answer, or None.

    In order: the whole text; the last `{"is_vulnerable"...}` object that decodes (a model that revises its verdict
    puts the revision last), repaired if the last one was cut off; the contents of the last code fence; the last
    balanced `{...}` span.
    """
    if not text:
        return None
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped
    decoder = json.JSONDecoder()
    starts = [m.start() for m in re.finditer(r'\{\s*"is_vulnerable"', text)]
    for pos in reversed(starts):
        try:
            _, end = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            if pos == starts[-1]:
                repaired = _close_truncated_object(text[pos:].strip())
                if repaired is not None:
                    return repaired
            continue
        return text[pos:end]
    repaired = _close_truncated_object(stripped)
    if repaired is not None:
        return repaired
    candidates = [
        block
        for match in re.finditer(r"```(?:json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
        if (block := match.group(1).strip()).startswith("{")
    ]
    candidates += _balanced_objects(text)
    return candidates[-1] if candidates else None


def parse_verdict(text: str) -> dict[str, Any]:
    """
    The verdict in an answer: `{is_vulnerable, cwe, vulnerable_lines, rationale, parse_error}`.

    A parse error carries the head of the answer as `raw`.
    """
    direct = parse_strict(text or "")
    if not direct["parse_error"]:
        return direct
    candidate = extract_json_object(text or "")
    if candidate is None:
        return _failed(text)
    recovered = parse_strict(candidate)
    if not recovered["parse_error"]:
        return recovered
    # An object that does not match the schema (a key missing, say) still counts when it says which way it decided.
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        return _failed(text)
    if isinstance(data, dict) and "is_vulnerable" in data:
        return {
            "is_vulnerable": bool(data.get("is_vulnerable")),
            "cwe": normalize_cwe(data.get("cwe")),
            "vulnerable_lines": data.get("vulnerable_lines") or [],
            "rationale": str(data.get("rationale") or ""),
            "parse_error": False,
        }
    return _failed(text)
