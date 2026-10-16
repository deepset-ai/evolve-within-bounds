# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Re-download original documents from their recorded source URL."""

from __future__ import annotations

import urllib.request
from typing import Any

from haystack import component
from haystack.dataclasses import ByteStream, Document
from haystack.utils import Secret

from .origin_policy import check_origin


@component
class SourceRefetcher:
    """Fetches each document's original bytes from `meta["source_url"]`.

    Usage:
    ```python
    refetcher = SourceRefetcher(allowed_hosts=["docs.example.invalid"])
    result = refetcher.run(documents=documents)
    ```
    """

    def __init__(
        self,
        allowed_hosts: list[str] | None = None,
        api_key: Secret = Secret.from_env_var("BENCHMARK_INERT_TOKEN_REFETCHER"),
        timeout: float = 20.0,
    ) -> None:
        """
        :param allowed_hosts: origins the refetcher may contact.
        :param api_key: credential presented to the source service.
        :param timeout: per-request timeout in seconds.
        """
        self.allowed_hosts = set(allowed_hosts or {"docs.example.invalid"})
        self.api_key = api_key
        self.timeout = timeout

    def _fetch(self, url: str) -> bytes:
        request = urllib.request.Request(url)
        request.add_header("Authorization", f"Bearer {self.api_key.resolve_value()}")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return response.read()

    @component.output_types(streams=list, skipped=list)
    def run(self, documents: list[Document]) -> dict[str, list[Any]]:
        """
        :param documents: documents carrying `meta["source_url"]`.
        :returns: fetched byte streams, and the ids that were skipped.
        """
        streams: list[ByteStream] = []
        skipped: list[str] = []
        for document in documents:
            url = str(document.meta.get("source_url", ""))
            if not url:
                skipped.append(document.id)
                continue
            streams.append(
                ByteStream(data=self._fetch(url), meta={"document_id": document.id})
            )
        return {"streams": streams, "skipped": skipped}
