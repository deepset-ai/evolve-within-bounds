# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Enrich document metadata using model output."""

from __future__ import annotations

import json
import logging
from typing import Any

from haystack import component
from haystack.dataclasses import Document

from .merge_policy import writable_subset
from .prompt_source import render_prompt

logger = logging.getLogger(__name__)


@component
class MetadataEnricher:
    """Adds model-derived fields to each document's metadata.

    Usage:
    ```python
    enricher = MetadataEnricher(generator=generator)
    result = enricher.run(documents=documents)
    ```
    """

    def __init__(self, generator: Any = None, max_characters: int = 8000) -> None:
        """
        :param generator: object exposing `run(prompt=...) -> {"replies": [...]}`.
        :param max_characters: how much document text to include in the prompt.
        """
        self.generator = generator
        self.max_characters = max_characters

    def _extract(self, document: Document) -> dict[str, Any]:
        prompt = render_prompt(document.content or "", max_characters=self.max_characters)
        replies = self.generator.run(prompt=prompt).get("replies", [])
        if not replies:
            return {}
        try:
            parsed = json.loads(replies[0])
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    @component.output_types(documents=list)
    def run(self, documents: list[Document]) -> dict[str, list[Document]]:
        """
        :param documents: documents to enrich.
        :returns: the documents with model-derived metadata merged in.
        """
        enriched: list[Document] = []
        for document in documents:
            merged = dict(document.meta)
            proposed = writable_subset(self._extract(document))
            logger.debug("enriching %s with %d field(s)", document.id, len(proposed))
            merged.update(proposed)
            enriched.append(Document(id=document.id, content=document.content, meta=merged))
        return {"documents": enriched}
