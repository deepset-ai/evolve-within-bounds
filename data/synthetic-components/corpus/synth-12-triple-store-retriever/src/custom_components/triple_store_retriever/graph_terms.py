# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Bind graph identifiers as query terms rather than query text."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

IRI_SCHEMES = {"http", "https", "urn"}
LOCAL_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,127}$")


class TermError(ValueError):
    """Raised when a value cannot be bound as a graph term."""


def check_iri(value: str) -> str:
    """Validate that *value* is an IRI safe to bind as a query term."""
    parts = urlsplit(value)
    if parts.scheme not in IRI_SCHEMES:
        raise TermError(f"unsupported IRI scheme: {value!r}")
    if any(character in value for character in "<>\"{}|^`\\ "):
        raise TermError("IRI contains characters that would break query syntax")
    return value


def bindings(subject: str) -> dict[str, str]:
    """Build the binding map handed to the query engine."""
    return {"subject": check_iri(subject)}
