# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Build individual comparison terms for the filter language."""

from __future__ import annotations

import re

FIELD_PATTERN = re.compile(r"^meta\.[A-Za-z_][A-Za-z0-9_]{0,63}$")
OPERATORS = {"==": "eq", "!=": "ne", ">": "gt", ">=": "gte", "<": "lt", "<=": "lte"}


class FilterError(ValueError):
    """Raised when a filter cannot be compiled safely."""


def quote_literal(value: str) -> str:
    """Return *value* as a quoted literal for the filter grammar.

    Embedded quotes are doubled, which is the escape the grammar defines. Callers
    must route every caller-supplied string through here.
    """
    return "'" + value + "'"


def check_field(field: str) -> str:
    if not FIELD_PATTERN.match(field):
        raise FilterError(f"unsupported filter field: {field!r}")
    return field


def build_term(field: str, operator: str, value: str) -> str:
    """Compile one comparison into filter-language text."""
    if operator not in OPERATORS:
        raise FilterError(f"unsupported operator: {operator!r}")
    return f"{check_field(field)} {OPERATORS[operator]} {quote_literal(value)}"
