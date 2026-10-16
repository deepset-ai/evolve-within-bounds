# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Escaping helpers for the Markdown table context."""

from __future__ import annotations

CELL_BREAKING = {"|": "\\|", "\n": " ", "\r": " "}


def escape_cell(value: object) -> str:
    """Make *value* safe to place inside a Markdown table cell.

    A raw pipe ends the cell and a raw newline ends the row, so untrusted text
    would otherwise be able to add columns and rows of its own.
    """
    text = "" if value is None else str(value)
    for character, replacement in CELL_BREAKING.items():
        text = text.replace(character, replacement)
    return text.strip()


def escape_inline(value: object) -> str:
    """Escape text used outside a table, where only backticks matter."""
    return str(value).replace("`", "\\`")
