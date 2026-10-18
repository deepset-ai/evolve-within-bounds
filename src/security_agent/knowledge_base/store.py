# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The Qdrant collection, and the record of what built it.

Two vectors per document: a dense one (bge-small) and a sparse BM25 one, which Qdrant fuses server-side. The
collection is created with `sparse_idf=True`: BM25 needs the IDF term, and without it the sparse leg is plain term
frequency.

The build record (embedding model, revision, source commit, document counts) is one point in a second collection,
`<index>__meta`, next to the data it describes. `check_model` refuses a collection built with another embedding model:
vectors from two models are not comparable, and the mismatch would otherwise only show as poor retrieval.

Qdrant runs in Docker (serving/qdrant/compose.yaml); tests use `":memory:"`.
"""

from __future__ import annotations

import json
from typing import Any

from security_agent.knowledge_base.settings import Settings

META_SUFFIX = "__meta"
META_POINT_ID = 0
SETUP_HINT = "Start Qdrant with `hatch run primevul:qdrant up -d`, then build it with `hatch run primevul:kb build`."


class KbStoreError(RuntimeError):
    """Qdrant is unreachable, the collection is missing, or it was built for another model."""


def _location(url: str) -> dict[str, Any]:
    return {"location": url} if url == ":memory:" else {"url": url}


def make_store(settings: Settings, *, recreate: bool = False, embedding_dim: int | None = None) -> Any:
    """Open (with `recreate`: drop and create) the collection; raises `KbStoreError` if Qdrant cannot be reached."""
    from haystack_integrations.document_stores.qdrant import QdrantDocumentStore

    try:
        store = QdrantDocumentStore(
            **_location(settings.qdrant_url),
            index=settings.qdrant_index,
            embedding_dim=embedding_dim or settings.embedding_dim,
            similarity="cosine",
            use_sparse_embeddings=True,
            sparse_idf=True,
            recreate_index=recreate,
            return_embedding=False,
            timeout=int(settings.qdrant_timeout),
        )
        # Connect now: the store connects lazily, and an unreachable Qdrant would otherwise surface wherever the first
        # query happens.
        store._initialize_client()
        return store
    except Exception as exc:
        raise KbStoreError(
            f"Cannot reach Qdrant at {settings.qdrant_url} ({type(exc).__name__}: {exc}). {SETUP_HINT}"
        ) from exc


def _client(store: Any) -> Any:
    """The store's own Qdrant client (an in-memory Qdrant lives inside it)."""
    store._initialize_client()
    return store._client


def write_meta(store: Any, meta: dict[str, Any], settings: Settings) -> None:
    """Record what this build produced, next to the collection."""
    from qdrant_client import models

    client = _client(store)
    collection = settings.qdrant_index + META_SUFFIX
    if not client.collection_exists(collection):
        client.create_collection(
            collection_name=collection, vectors_config=models.VectorParams(size=1, distance=models.Distance.DOT)
        )
    client.upsert(
        collection_name=collection,
        points=[models.PointStruct(id=META_POINT_ID, vector=[0.0], payload={"kb_meta": json.dumps(meta)})],
    )


def read_meta(store: Any, settings: Settings) -> dict[str, Any]:
    """The build record; raises `KbStoreError` if the knowledge base was never built."""
    collection = settings.qdrant_index + META_SUFFIX
    try:
        client = _client(store)
        exists = client.collection_exists(collection)
        points = client.retrieve(collection_name=collection, ids=[META_POINT_ID], with_payload=True) if exists else []
    except Exception as exc:
        raise KbStoreError(
            f"Cannot read the knowledge base's build record from {settings.qdrant_url} ({type(exc).__name__}: {exc}). "
            f"{SETUP_HINT}"
        ) from exc
    if not exists:
        raise KbStoreError(f"No knowledge base in Qdrant at {settings.qdrant_url}. {SETUP_HINT}")
    if not points:
        raise KbStoreError(f"The knowledge base at {settings.qdrant_url} has no build record. {SETUP_HINT}")
    return json.loads(points[0].payload["kb_meta"])


def check_model(meta: dict[str, Any], embedding_model: str | None) -> None:
    """Refuse a collection built with another embedding model."""
    built = meta.get("embedding_model")
    if embedding_model and built and embedding_model != built:
        raise KbStoreError(
            f"The knowledge base was built with {built!r}, but the agent searches it with {embedding_model!r}. "
            f"Rebuild it with `hatch run primevul:kb build`."
        )


def source_counts(store: Any) -> dict[str, int]:
    """Documents per source, counted in the collection."""
    values, _ = store.get_metadata_field_unique_values("source", size=100)
    return {
        source: store.count_documents_by_filter(filters={"field": "meta.source", "operator": "==", "value": source})
        for source in sorted(values)
    }
