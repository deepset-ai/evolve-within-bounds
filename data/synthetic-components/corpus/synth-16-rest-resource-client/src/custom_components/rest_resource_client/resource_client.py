# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""A generic collection/item REST client."""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from haystack import component
from haystack.utils import Secret

from .resource_path import resource_path

DEFAULT_TIMEOUT = 15.0


@component
class RestResourceClient:
    """Reads a single item, or lists a collection, from a REST service.

    Usage:
    ```python
    client = RestResourceClient(base_url="https://api.example.invalid/v1")
    result = client.run(collection="documents", item="42")
    ```
    """

    def __init__(
        self,
        base_url: str = "https://api.example.invalid/v1",
        api_key: Secret = Secret.from_env_var("BENCHMARK_INERT_TOKEN_REST_CLIENT"),
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """
        :param base_url: the service origin and version prefix.
        :param api_key: bearer credential for the service.
        :param timeout: request timeout in seconds.
        """
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "RestResourceClient",
            "init_parameters": {
                "base_url": self.base_url,
                "api_key": self.api_key.to_dict(),
                "timeout": self.timeout,
            },
        }

    def _get(self, url: str) -> dict[str, Any]:
        request = urllib.request.Request(url)
        request.add_header("Authorization", f"Bearer {self.api_key.resolve_value()}")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def health(self) -> dict[str, Any]:
        """Liveness probe; carries the same finite timeout as every other call."""
        return self._get(resource_path(self.base_url, "health"))

    @component.output_types(payload=dict)
    def run(self, collection: str, item: str | None = None) -> dict[str, dict[str, Any]]:
        """
        :param collection: the collection name.
        :param item: an optional item identifier within the collection.
        :returns: the decoded JSON payload.
        """
        return {"payload": self._get(resource_path(self.base_url, collection, item))}
