# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Retrieve triples for a subject from a graph endpoint."""

from __future__ import annotations

from typing import Any

from haystack import component
from haystack.dataclasses import Document

from .graph_terms import bindings

SUBJECT_QUERY = """
SELECT ?predicate ?object
WHERE { ?subject ?predicate ?object }
LIMIT %(limit)d
"""


@component
class TripleStoreRetriever:
    """Fetches predicate/object pairs for a subject IRI.

    Usage:
    ```python
    retriever = TripleStoreRetriever(client=client)
    result = retriever.run(subject="https://graph.example.invalid/entity/1")
    ```
    """

    def __init__(self, client: Any = None, limit: int = 100) -> None:
        """
        :param client: a graph client exposing `query(text, bindings)`.
        :param limit: maximum number of triples to return.
        """
        self.client = client
        self.limit = limit

    @component.output_types(documents=list)
    def run(self, subject: str) -> dict[str, list[Document]]:
        """
        :param subject: the subject IRI to describe.
        :returns: one document per retrieved triple.
        """
        rows = self.client.query(SUBJECT_QUERY % {"limit": self.limit}, bindings(subject))
        return {
            "documents": [
                Document(content=str(row["object"]), meta={"predicate": row["predicate"]})
                for row in rows
            ]
        }
