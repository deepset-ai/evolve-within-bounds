# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Propagate tags from parent documents to their splits."""

from __future__ import annotations

from typing import Any

from haystack import component
from haystack.dataclasses import Document

INHERITABLE_TAGS = frozenset({"topics", "category", "language", "collection"})


def inheritable(parent_meta: dict[str, Any]) -> dict[str, Any]:
    """Return only the parent fields a split is allowed to inherit.

    Splits are indexed as independent documents, so inheriting an unrestricted
    set would let a parent's fields land on rows the caller can already read.
    """
    return dict(parent_meta)


@component
class TagPropagator:
    """Copies inheritable parent tags onto each split document.

    Usage:
    ```python
    propagator = TagPropagator()
    result = propagator.run(parents=parents, splits=splits)
    ```
    """

    def __init__(self, parent_key: str = "parent_id") -> None:
        """
        :param parent_key: split metadata key naming the parent document id.
        """
        self.parent_key = parent_key

    @component.output_types(documents=list)
    def run(self, parents: list[Document], splits: list[Document]) -> dict[str, list[Document]]:
        """
        :param parents: the original documents.
        :param splits: the split documents referencing their parent.
        :returns: the splits with inherited tags applied.
        """
        by_id = {parent.id: parent for parent in parents}
        result: list[Document] = []
        for split in splits:
            meta = dict(split.meta)
            parent = by_id.get(str(split.meta.get(self.parent_key, "")))
            if parent is not None:
                for key, value in inheritable(parent.meta).items():
                    meta.setdefault(key, value)
            result.append(Document(id=split.id, content=split.content, meta=meta))
        return {"documents": result}
