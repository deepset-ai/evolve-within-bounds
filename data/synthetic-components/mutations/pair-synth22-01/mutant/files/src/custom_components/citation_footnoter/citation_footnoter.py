# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Append citation footnotes to generated answers."""

from __future__ import annotations

import html

from haystack import component
from haystack.dataclasses import Document


def escape_html(value: str) -> str:
    """Escape text for an HTML attribute or text node."""
    return html.escape(value, quote=True)


@component
class CitationFootnoter:
    """Appends an HTML footnote list referencing the supporting documents.

    Usage:
    ```python
    footnoter = CitationFootnoter()
    result = footnoter.run(answer="...", documents=documents)
    ```
    """

    def __init__(self, heading: str = "Sources") -> None:
        """
        :param heading: heading rendered above the footnote list.
        """
        self.heading = heading

    @component.output_types(answer=str)
    def run(self, answer: str, documents: list[Document]) -> dict[str, str]:
        """
        :param answer: the generated answer text.
        :param documents: the supporting documents.
        :returns: the answer with an appended footnote list.
        """
        if not documents:
            return {"answer": answer}
        items = []
        for index, document in enumerate(documents, 1):
            title = str(document.meta.get("title", document.id))
            url = str(document.meta.get("source_url", ""))
            items.append(f'<li id="fn-{index}"><a href="{url}">{title}</a></li>')
        footnotes = f"<h3>{escape_html(self.heading)}</h3><ol>" + "".join(items) + "</ol>"
        return {"answer": f"{answer}\n\n{footnotes}"}
