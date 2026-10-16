# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Read blobs by key from an object store gateway."""

from __future__ import annotations

import urllib.request
from urllib.parse import quote

from haystack import component
from haystack.dataclasses import ByteStream


class ObjectKeyError(ValueError):
    """Raised when an object key cannot be expressed as a path."""


def encode_key(key: str) -> str:
    """Encode an object key, preserving `/` as the store's own separator.

    Traversal segments are rejected outright rather than encoded, because the
    gateway resolves `..` server-side before the bucket ACL is applied.
    """
    text = str(key).strip().lstrip("/")
    if not text:
        raise ObjectKeyError("object key is empty")
    return "/".join(quote(part, safe="") for part in text.split("/"))


@component
class ObjectStoreReader:
    """Downloads objects from a gateway and yields them as byte streams.

    Usage:
    ```python
    reader = ObjectStoreReader(base_url="https://objects.example.invalid")
    result = reader.run(keys=["reports/2026/q1.pdf"])
    ```
    """

    def __init__(
        self,
        base_url: str = "https://objects.example.invalid",
        bucket: str = "documents",
        timeout: float = 30.0,
    ) -> None:
        """
        :param base_url: object gateway origin.
        :param bucket: bucket every key is read from.
        :param timeout: per-object timeout in seconds.
        """
        self.base_url = base_url
        self.bucket = bucket
        self.timeout = timeout

    @component.output_types(streams=list)
    def run(self, keys: list[str]) -> dict[str, list[ByteStream]]:
        """
        :param keys: object keys to download.
        :returns: one byte stream per key.
        """
        streams: list[ByteStream] = []
        for key in keys:
            url = f"{self.base_url.rstrip('/')}/{quote(self.bucket, safe='')}/{encode_key(key)}"
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                streams.append(ByteStream(data=response.read(), meta={"object_key": key}))
        return {"streams": streams}
