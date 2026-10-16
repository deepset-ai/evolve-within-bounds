# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Load assets referenced by a document during conversion."""

from __future__ import annotations

import urllib.request
from urllib.parse import urljoin, urlsplit

from haystack import component
from haystack.dataclasses import ByteStream, Document


class AssetRejected(ValueError):
    """Raised when a referenced asset is outside the document's own origin."""


def same_origin(document_url: str, asset_reference: str) -> str:
    """Resolve *asset_reference* against the document and require the same origin.

    Assets are named inside the document body, so the only trustworthy anchor is
    the origin the document itself came from.
    """
    return urljoin(document_url, asset_reference)


@component
class RemoteAssetLoader:
    """Downloads the assets a document references, staying on its origin.

    Usage:
    ```python
    loader = RemoteAssetLoader()
    result = loader.run(document=document, references=["images/a.png"])
    ```
    """

    def __init__(self, timeout: float = 15.0, max_assets: int = 32) -> None:
        """
        :param timeout: per-asset timeout in seconds.
        :param max_assets: how many assets to load per document.
        """
        self.timeout = timeout
        self.max_assets = max_assets

    @component.output_types(assets=list)
    def run(self, document: Document, references: list[str]) -> dict[str, list[ByteStream]]:
        """
        :param document: the document carrying `meta["document_url"]`.
        :param references: asset references found in the document body.
        :returns: the loaded assets.
        """
        document_url = str(document.meta.get("document_url", ""))
        assets: list[ByteStream] = []
        for reference in references[: self.max_assets]:
            url = same_origin(document_url, reference)
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                assets.append(ByteStream(data=response.read(), meta={"asset_url": url}))
        return {"assets": assets}
