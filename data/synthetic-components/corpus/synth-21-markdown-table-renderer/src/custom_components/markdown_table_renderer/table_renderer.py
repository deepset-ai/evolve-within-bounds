# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Render retrieved rows as a Markdown table."""

from __future__ import annotations

from typing import Any

from haystack import component

from .markdown_escape import escape_cell, escape_inline


@component
class MarkdownTableRenderer:
    """Renders a list of row mappings as a Markdown table.

    Usage:
    ```python
    renderer = MarkdownTableRenderer(columns=["name", "status"])
    result = renderer.run(rows=[{"name": "alpha", "status": "live"}])
    ```
    """

    def __init__(self, columns: list[str] | None = None, caption: str = "") -> None:
        """
        :param columns: column order; defaults to the keys of the first row.
        :param caption: optional caption rendered above the table.
        """
        self.columns = list(columns or [])
        self.caption = caption

    @component.output_types(markdown=str)
    def run(self, rows: list[dict[str, Any]]) -> dict[str, str]:
        """
        :param rows: the row mappings to render.
        :returns: the rendered Markdown table.
        """
        if not rows:
            return {"markdown": ""}
        columns = self.columns or list(rows[0].keys())
        lines = []
        if self.caption:
            lines.append(f"**{escape_inline(self.caption)}**")
            lines.append("")
        lines.append("| " + " | ".join(escape_cell(column) for column in columns) + " |")
        lines.append("| " + " | ".join("---" for _ in columns) + " |")
        for row in rows:
            cells = [escape_cell(row.get(column)) for column in columns]
            lines.append("| " + " | ".join(cells) + " |")
        return {"markdown": "\n".join(lines)}
