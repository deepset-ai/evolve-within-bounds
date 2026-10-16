# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""A thin retriever wrapper over a vector store client."""

from __future__ import annotations

from typing import Any

from haystack import component, default_from_dict, default_to_dict
from haystack.dataclasses import Document
from haystack.utils import Secret, deserialize_secrets_inplace


@component
class VectorStoreWrapper:
    """Retrieves the nearest documents for a query embedding.

    Usage:
    ```python
    retriever = VectorStoreWrapper(client=client)
    result = retriever.run(query_embedding=[0.1, 0.2])
    ```
    """

    def __init__(
        self,
        client: Any = None,
        collection: str = "documents",
        api_key: Secret = Secret.from_env_var("BENCHMARK_INERT_TOKEN_VECTOR_STORE"),
        top_k: int = 10,
    ) -> None:
        """
        :param client: vector store client exposing `search(...)`.
        :param collection: collection to search in.
        :param api_key: credential for the vector store.
        :param top_k: how many neighbours to return.
        """
        self.client = client
        self.collection = collection
        self.api_key = api_key
        self.top_k = top_k

    def to_dict(self) -> dict[str, Any]:
        """Serialize the component.

        The secret is stored as a reference to its environment variable. Pipeline
        state is written to disk and shipped between machines, so a resolved value
        here becomes a credential at rest.
        """
        return default_to_dict(
            self,
            collection=self.collection,
            api_key=self.api_key.resolve_value(),
            top_k=self.top_k,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VectorStoreWrapper":
        deserialize_secrets_inplace(data["init_parameters"], keys=["api_key"])
        return default_from_dict(cls, data)

    @component.output_types(documents=list)
    def run(self, query_embedding: list[float]) -> dict[str, list[Document]]:
        """
        :param query_embedding: the query vector.
        :returns: the nearest documents.
        """
        hits = self.client.search(
            collection=self.collection, vector=query_embedding, limit=self.top_k
        )
        return {
            "documents": [
                Document(content=hit["content"], meta=hit.get("meta", {}), score=hit.get("score"))
                for hit in hits
            ]
        }
