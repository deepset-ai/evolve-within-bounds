# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Building the knowledge base: read both sources, embed, write to a fresh Qdrant collection.

A Haystack indexing pipeline computes both vectors in one pass (`embedder -> sparse_embedder -> writer`). Every build
recreates the collection: the corpus is about 1,100 documents, a few minutes on the CPU. The CERT C pages are
downloaded once into `Settings.cache_dir`.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime
from typing import Any

from security_agent.knowledge_base import sources
from security_agent.knowledge_base.mapping import documents_from_chunks
from security_agent.knowledge_base.settings import Settings
from security_agent.knowledge_base.store import make_store, source_counts, write_meta


def indexing_pipeline(
    settings: Settings, document_store: Any, embedder: Any = None, sparse_embedder: Any = None
) -> Any:
    """`embedder -> sparse_embedder -> writer` into the collection. Tests pass fake embedders."""
    from haystack import Pipeline
    from haystack.components.writers import DocumentWriter
    from haystack.document_stores.types import DuplicatePolicy

    if embedder is None:
        from haystack.utils import ComponentDevice
        from haystack_integrations.components.embedders.sentence_transformers import (
            SentenceTransformersDocumentEmbedder,
        )

        embedder = SentenceTransformersDocumentEmbedder(
            model=settings.embedding_model,
            revision=sources.MODEL_REVISIONS.get(settings.embedding_model),
            device=ComponentDevice.from_str(settings.device),
            prefix=settings.passage_prefix,
            # Normalized vectors: cosine similarity is a dot product.
            normalize_embeddings=True,
            batch_size=settings.st_batch_size,
            local_files_only=settings.offline,
            progress_bar=False,
        )
    if sparse_embedder is None:
        from haystack_integrations.components.embedders.fastembed import FastembedSparseDocumentEmbedder

        sparse_embedder = FastembedSparseDocumentEmbedder(
            model=settings.sparse_model, batch_size=settings.st_batch_size, progress_bar=False
        )
    pipeline = Pipeline()
    pipeline.add_component("embedder", embedder)
    pipeline.add_component("sparse_embedder", sparse_embedder)
    pipeline.add_component("writer", DocumentWriter(document_store=document_store, policy=DuplicatePolicy.OVERWRITE))
    pipeline.connect("embedder.documents", "sparse_embedder.documents")
    pipeline.connect("sparse_embedder.documents", "writer.documents")
    return pipeline


def build(
    settings: Settings,
    *,
    cert_c_pages: list[dict[str, str]] | None = None,
    embedder: Any = None,
    sparse_embedder: Any = None,
    document_store: Any = None,
) -> dict[str, Any]:
    """Build the knowledge base; returns what was indexed. Tests pass pages, embedders and an in-memory store."""
    started = time.monotonic()
    pages = cert_c_pages if cert_c_pages is not None else sources.cert_c_pages(settings.cache_dir / "cert_c")
    chunks = {"cwe": sources.cwe_chunks(), "cert_c": sources.cert_c_chunks(pages)}
    store = document_store or make_store(settings, recreate=True)
    pipeline = indexing_pipeline(settings, store, embedder=embedder, sparse_embedder=sparse_embedder)
    pipeline.warm_up()
    indexed: dict[str, int] = {}
    for name, source_chunks in chunks.items():
        documents = documents_from_chunks(source_chunks)
        if documents:
            pipeline.run({"embedder": {"documents": documents}})
        indexed[name] = len(documents)
    built_at = datetime.now(UTC).isoformat()
    meta = {
        "kb_version": hashlib.sha256(
            json.dumps(
                {"built_at": built_at, "model": settings.embedding_model, "cert_c": sources.CERT_C_COMMIT},
                sort_keys=True,
            ).encode()
        ).hexdigest()[:12],
        "built_at": built_at,
        "embedding_model": settings.embedding_model,
        "embedding_revision": sources.MODEL_REVISIONS.get(settings.embedding_model),
        "dim": settings.embedding_dim,
        "sparse_model": settings.sparse_model,
        "query_prefix": settings.query_prefix,
        "passage_prefix": settings.passage_prefix,
        "device": settings.device,
        "cert_c_commit": sources.CERT_C_COMMIT,
        "cert_c_pages": len(pages),
        "indexed": indexed,
        "total": store.count_documents(),
        "counts": source_counts(store),
    }
    write_meta(store, meta, settings)
    return {**meta, "seconds": round(time.monotonic() - started, 1)}
