# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Wrap a web search API as a Haystack retriever."""

from __future__ import annotations

import json
import urllib.request
from typing import Any
from urllib.parse import urlencode

from haystack import component
from haystack.dataclasses import Document
from haystack.utils import Secret

MAX_QUERY_LENGTH = 512


class SearchError(ValueError):
    """Raised when a query cannot be sent to the search API."""


@component
class WebSearchBridge:
    """Runs a query against a web search API and returns result documents.

    Usage:
    ```python
    bridge = WebSearchBridge()
    result = bridge.run(query="haystack custom components")
    ```
    """

    def __init__(
        self,
        endpoint: str = "https://search.example.invalid/v1/search",
        api_key: Secret = Secret.from_env_var("BENCHMARK_INERT_TOKEN_WEBSEARCH"),
        top_k: int = 10,
        timeout: float = 20.0,
    ) -> None:
        """
        :param endpoint: search API endpoint.
        :param api_key: credential resolved from the environment at call time.
        :param top_k: how many results to request.
        :param timeout: request timeout in seconds.
        """
        self.endpoint = endpoint
        self.api_key = api_key
        self.top_k = top_k
        self.timeout = timeout

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "WebSearchBridge",
            "init_parameters": {
                "endpoint": self.endpoint,
                "api_key": self.api_key.to_dict(),
                "top_k": self.top_k,
                "timeout": self.timeout,
            },
        }

    def _check_query(self, query: str) -> str:
        text = query.strip()
        if not text:
            raise SearchError("query is empty")
        if len(text) > MAX_QUERY_LENGTH:
            raise SearchError("query is too long")
        return text

    @component.output_types(documents=list)
    def run(self, query: str) -> dict[str, list[Document]]:
        """
        :param query: the search text.
        :returns: one document per search result.
        """
        parameters = urlencode({"q": self._check_query(query), "count": self.top_k})
        request = urllib.request.Request(f"{self.endpoint}?{parameters}")
        token = self.api_key.resolve_value()
        if not token:
            raise SearchError("search credential is not configured")
        request.add_header("X-Subscription-Token", token)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
        return {
            "documents": [
                Document(content=item.get("snippet", ""), meta={"url": item.get("url", "")})
                for item in body.get("results", [])[: self.top_k]
            ]
        }
