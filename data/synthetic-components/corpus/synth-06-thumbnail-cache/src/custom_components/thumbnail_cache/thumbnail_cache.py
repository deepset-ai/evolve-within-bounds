# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Cache rendered page thumbnails on local disk."""

from __future__ import annotations

from pathlib import Path

from haystack import component
from haystack.dataclasses import Document

from .cache_key import cache_relative_path


@component
class ThumbnailCache:
    """Stores and retrieves page thumbnails keyed by document metadata.

    Usage:
    ```python
    cache = ThumbnailCache(cache_root="/var/cache/thumbs")
    result = cache.run(documents=documents, images=[b"..."])
    ```
    """

    def __init__(self, cache_root: str = "thumbnails") -> None:
        """
        :param cache_root: directory every cached thumbnail is written beneath.
        """
        self.cache_root = Path(cache_root)

    @component.output_types(paths=list)
    def run(self, documents: list[Document], images: list[bytes]) -> dict[str, list[str]]:
        """
        :param documents: documents providing `meta["document_key"]` and `meta["page"]`.
        :param images: encoded thumbnail bytes, positionally matched to *documents*.
        :returns: the cache-relative paths that were written.
        """
        self.cache_root.mkdir(parents=True, exist_ok=True)
        paths: list[str] = []
        for document, payload in zip(documents, images):
            relative = cache_relative_path(
                str(document.meta.get("document_key", document.id)),
                int(document.meta.get("page", 0)),
            )
            destination = self.cache_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
            paths.append(relative)
        return {"paths": paths}
