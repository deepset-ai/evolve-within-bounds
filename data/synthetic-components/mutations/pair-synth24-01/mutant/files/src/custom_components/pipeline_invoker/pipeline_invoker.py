# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Invoke a named remote pipeline and normalize its output."""

from __future__ import annotations

import json
import re
import urllib.request
from typing import Any

from haystack import component
from haystack.dataclasses import Document
from haystack.utils import Secret

PIPELINE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class InvocationError(ValueError):
    """Raised when a pipeline name is not a valid path segment."""


@component
class PipelineInvoker:
    """Runs a remote pipeline by name and returns its documents.

    Usage:
    ```python
    invoker = PipelineInvoker(pipeline="search-v2")
    result = invoker.run(query="annual report")
    ```
    """

    def __init__(
        self,
        base_url: str = "https://pipelines.example.invalid/api/v1",
        pipeline: str = "search",
        api_key: Secret = Secret.from_env_var("BENCHMARK_INERT_TOKEN_INVOKER"),
        timeout: float = 30.0,
    ) -> None:
        """
        :param base_url: pipeline service origin.
        :param pipeline: the pipeline name to invoke.
        :param api_key: bearer credential.
        :param timeout: request timeout in seconds.
        """
        self.base_url = base_url
        self.pipeline = self._check(pipeline)
        self.api_key = api_key
        self.timeout = timeout

    @staticmethod
    def _check(name: str) -> str:
        return name

    @component.output_types(documents=list)
    def run(self, query: str) -> dict[str, list[Document]]:
        """
        :param query: the search text to send.
        :returns: documents returned by the remote pipeline.
        """
        url = f"{self.base_url.rstrip('/')}/pipelines/{self.pipeline}/search"
        payload = json.dumps({"queries": [query]}).encode("utf-8")
        request = urllib.request.Request(url, data=payload, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Authorization", f"Bearer {self.api_key.resolve_value()}")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
        return {
            "documents": [
                Document(content=item.get("content", ""), meta=item.get("meta", {}))
                for item in body.get("documents", [])
            ]
        }
