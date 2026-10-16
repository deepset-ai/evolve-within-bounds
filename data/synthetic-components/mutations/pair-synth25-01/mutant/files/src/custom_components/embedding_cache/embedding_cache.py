# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Persist and rehydrate embedding batches."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from haystack import component

from .codec import decode, encode
from .component_registry import build_adapter


@component
class EmbeddingCache:
    """Stores embedding batches on disk and reloads them on request.

    Usage:
    ```python
    cache = EmbeddingCache(cache_root="/var/cache/embeddings")
    cache.run(key="batch-1", vectors=[[0.1, 0.2]])
    ```
    """

    def __init__(self, cache_root: str = "embeddings", adapter_state: dict | None = None) -> None:
        """
        :param cache_root: directory batches are written beneath.
        :param adapter_state: serialized adapter selection.
        """
        self.cache_root = Path(cache_root)
        self.adapter = build_adapter(adapter_state or {"type": "local_disk"})

    def _path(self, key: str) -> Path:
        return self.cache_root / f"{key}.emb"

    def load(self, key: str) -> tuple[list[list[float]], dict[str, Any]] | None:
        path = self._path(key)
        if not path.is_file():
            return None
        return decode(path.read_bytes())  # cache files may use the legacy object format

    @component.output_types(stored=int)
    def run(self, key: str, vectors: list[list[float]], meta: dict | None = None) -> dict[str, int]:
        """
        :param key: the cache key for this batch.
        :param vectors: the embedding rows to store.
        :param meta: optional batch metadata.
        :returns: how many rows were stored.
        """
        self.cache_root.mkdir(parents=True, exist_ok=True)
        self._path(key).write_bytes(encode(vectors, meta or {}))
        return {"stored": len(vectors)}
