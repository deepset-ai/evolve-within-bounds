# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Map source fields onto a canonical metadata schema."""

from __future__ import annotations

from typing import Any

from haystack import component
from haystack.dataclasses import Document

CANONICAL_FIELDS = frozenset({"title", "author", "published_at", "category", "language"})


class MappingError(ValueError):
    """Raised when a mapping targets a field outside the canonical schema."""


def check_mapping(mapping: dict[str, str]) -> dict[str, str]:
    """Validate that every mapping target is a canonical field."""
    unknown = sorted(set(mapping.values()) - CANONICAL_FIELDS)
    if unknown:
        raise MappingError(f"mapping targets are not canonical fields: {unknown}")
    return dict(mapping)


@component
class SchemaMapper:
    """Renames source metadata fields onto the canonical schema.

    Usage:
    ```python
    mapper = SchemaMapper(mapping={"headline": "title"})
    result = mapper.run(documents=documents)
    ```
    """

    def __init__(self, mapping: dict[str, str] | None = None, drop_unmapped: bool = False) -> None:
        """
        :param mapping: source field name to canonical field name.
        :param drop_unmapped: whether to discard source fields with no mapping.
        """
        self.mapping = check_mapping(mapping or {})
        self.drop_unmapped = drop_unmapped

    @component.output_types(documents=list)
    def run(self, documents: list[Document]) -> dict[str, list[Document]]:
        """
        :param documents: documents whose metadata should be mapped.
        :returns: documents carrying canonical metadata.
        """
        mapped: list[Document] = []
        for document in documents:
            meta: dict[str, Any] = {} if self.drop_unmapped else dict(document.meta)
            for source, target in self.mapping.items():
                if source in document.meta:
                    meta[target] = document.meta[source]
                    meta.pop(source, None)
            mapped.append(Document(id=document.id, content=document.content, meta=meta))
        return {"documents": mapped}
