# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Validate model-authored SQL before it reaches the warehouse."""

from __future__ import annotations

import re

STATEMENT = re.compile(r"^\s*select\b", re.IGNORECASE)
FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|grant|copy|attach|pragma)\b", re.IGNORECASE
)
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class QueryRejected(ValueError):
    """Raised when a generated query is not provably read-only."""


def check_read_only(sql: str) -> str:
    """Return *sql* if it is a single read-only statement, else raise."""
    if ";" in sql.rstrip().rstrip(";"):
        raise QueryRejected("only a single statement is allowed")
    return sql


def check_table(name: str, allowed: set[str]) -> str:
    if not IDENTIFIER.match(name) or name not in allowed:
        raise QueryRejected(f"table is not in the catalog: {name!r}")
    return name
