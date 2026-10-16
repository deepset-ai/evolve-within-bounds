# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Build the enrichment prompt from a fixed template."""

from __future__ import annotations

from typing import Any

ENRICHMENT_TEMPLATE = (
    "Summarize the document and list its topics.\n"
    "Return JSON with keys summary and topics.\n"
    "---\n"
    "{document_text}\n"
)


def render_prompt(document_text: str, *, max_characters: int = 8000) -> str:
    """Render the enrichment prompt.

    The template is a constant and the document is substituted as *data*. Building
    template source by concatenation would let document text become instructions.
    """
    clipped = document_text[:max_characters]
    from string import Template

    return Template(ENRICHMENT_TEMPLATE.replace("{document_text}", clipped)).substitute()


def describe_template() -> dict[str, Any]:
    return {"template": ENRICHMENT_TEMPLATE, "variables": ["document_text"]}
