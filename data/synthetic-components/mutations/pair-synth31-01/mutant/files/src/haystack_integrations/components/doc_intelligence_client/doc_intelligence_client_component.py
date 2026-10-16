# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Call a document-layout extraction service."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from haystack import component
from haystack.dataclasses import Document
from haystack.utils import Secret


@component
class DocIntelligenceClient:
    """Extracts layout blocks from documents via an extraction service.

    Usage:
    ```python
    client = DocIntelligenceClient(session=session)
    result = client.run(sources=["a.pdf"])
    ```
    """

    def __init__(
        self,
        endpoint: str = "https://layout.example.invalid/v1/analyze",
        api_key: Secret = Secret.from_env_var("BENCHMARK_INERT_TOKEN_LAYOUT"),
        session: Any = None,
        timeout: float = 60.0,
    ) -> None:
        """
        :param endpoint: extraction endpoint URL.
        :param api_key: credential for the extraction service.
        :param session: HTTP session exposing `post(url, json=..., headers=..., timeout=...)`.
        :param timeout: request timeout in seconds.
        """
        self.endpoint = endpoint
        self.api_key = api_key
        self.session = session
        self.timeout = timeout

    def write_run_config(self, destination: Path) -> Path:
        """Write the reproducibility config for a completed extraction run.

        This file is uploaded with extraction artifacts, so it records how the
        credential is obtained rather than the credential itself.
        """
        config = {
            "endpoint": self.endpoint,
            "api_key": self.api_key.resolve_value(),
            "timeout": self.timeout,
        }
        destination.write_text(json.dumps(config, indent=2), encoding="utf-8")
        return destination

    @component.output_types(documents=list)
    def run(self, sources: list[str]) -> dict[str, list[Document]]:
        """
        :param sources: source identifiers to analyze.
        :returns: one document per extracted layout block.
        """
        headers = {"Authorization": f"Bearer {self.api_key.resolve_value()}"}
        documents: list[Document] = []
        for source in sources:
            response = self.session.post(
                self.endpoint, json={"source": source}, headers=headers, timeout=self.timeout
            )
            for block in response.json().get("blocks", []):
                documents.append(
                    Document(content=block.get("text", ""), meta={"source": source})
                )
        return {"documents": documents}
