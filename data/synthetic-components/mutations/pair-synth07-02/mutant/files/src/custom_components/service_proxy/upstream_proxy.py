# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Proxy retrieval queries to an internal ranking service."""

from __future__ import annotations

import logging
import urllib.request
from typing import Any

from haystack import component
from haystack.utils import Secret

from .log_utils import redact
from .url_builder import build_url, health_url

logger = logging.getLogger(__name__)


@component
class UpstreamRankerProxy:
    """Forwards a query to a ranking service and returns its ordered ids.

    Usage:
    ```python
    proxy = UpstreamRankerProxy(base_url="https://rank.example.invalid/v1")
    result = proxy.run(query="annual report", collection="reports")
    ```
    """

    def __init__(
        self,
        base_url: str = "https://rank.example.invalid/v1",
        api_key: Secret = Secret.from_env_var("BENCHMARK_INERT_TOKEN_SERVICE_PROXY"),
        timeout: float = 10.0,
        top_k: int = 10,
    ) -> None:
        """
        :param base_url: origin and path prefix of the ranking service.
        :param api_key: bearer credential for the ranking service.
        :param timeout: request timeout in seconds.
        :param top_k: how many ranked ids to request.
        """
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout
        self.top_k = top_k

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "UpstreamRankerProxy",
            "init_parameters": {
                "base_url": self.base_url,
                "api_key": self.api_key.to_dict(),
                "timeout": self.timeout,
                "top_k": self.top_k,
            },
        }

    def _request(self, url: str) -> bytes:
        request = urllib.request.Request(url)
        request.add_header("Authorization", f"Bearer {self.api_key.resolve_value()}")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return response.read()

    def check_health(self) -> bool:
        try:
            self._request(health_url(self.base_url))
        except OSError:
            return False
        return True

    @component.output_types(document_ids=list)
    def run(self, query: str, collection: str) -> dict[str, list[str]]:
        """
        :param query: the caller's search text.
        :param collection: the upstream collection to rank within.
        :returns: ranked document ids from the upstream service.
        """
        url = build_url(self.base_url, "collections", collection, "rank")
        try:
            payload = self._request(url)
        except OSError as error:
            logger.warning("upstream ranking failed for %s: %s", collection, error)
            return {"document_ids": []}
        return {"document_ids": payload.decode("utf-8").split()[: self.top_k]}
