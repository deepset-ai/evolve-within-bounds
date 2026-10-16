# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""List and page a remote collection API."""

from __future__ import annotations

import json
import urllib.request
from typing import Any
from urllib.parse import quote, urlencode

from haystack import component


class BrowseError(ValueError):
    """Raised when a collection name cannot be placed in a path."""


def collection_segment(name: str) -> str:
    """Percent-encode a collection name for use as one path segment."""
    text = str(name).strip()
    if not text:
        raise BrowseError("collection name is empty")
    return quote(text, safe="")


@component
class CollectionBrowser:
    """Pages through a remote collection and returns the accumulated items.

    Usage:
    ```python
    browser = CollectionBrowser(base_url="https://api.example.invalid/v1")
    result = browser.run(collection="documents")
    ```
    """

    def __init__(
        self,
        base_url: str = "https://api.example.invalid/v1",
        page_size: int = 50,
        max_pages: int = 20,
        timeout: float = 15.0,
    ) -> None:
        """
        :param base_url: the collection service origin.
        :param page_size: how many items to request per page.
        :param max_pages: how many pages to walk before stopping.
        :param timeout: per-request timeout in seconds.
        """
        self.base_url = base_url
        self.page_size = page_size
        self.max_pages = max_pages
        self.timeout = timeout

    def _page_url(self, collection: str, cursor: str | None) -> str:
        query = {"limit": self.page_size}
        if cursor:
            query["after"] = cursor
        segment = collection_segment(collection)
        return f"{self.base_url.rstrip('/')}/collections/{segment}/items?{urlencode(query)}"

    @component.output_types(items=list)
    def run(self, collection: str) -> dict[str, list[Any]]:
        """
        :param collection: the collection to enumerate.
        :returns: every item across the walked pages.
        """
        items: list[Any] = []
        cursor: str | None = None
        for _ in range(self.max_pages):
            url = self._page_url(collection, cursor)
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                page = json.loads(response.read().decode("utf-8"))
            items.extend(page.get("items", []))
            cursor = page.get("next_cursor")
            if not cursor:
                break
        return {"items": items}
