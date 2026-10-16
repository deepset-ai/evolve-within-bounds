# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Caption page images with a multimodal endpoint."""

from __future__ import annotations

import base64
import json
import urllib.request
from typing import Any

from haystack import component
from haystack.dataclasses import ByteStream
from haystack.utils import Secret


@component
class VisionCaptioner:
    """Sends page images to a captioning endpoint and returns the captions.

    Usage:
    ```python
    captioner = VisionCaptioner()
    result = captioner.run(images=[stream])
    ```
    """

    def __init__(
        self,
        endpoint: str = "https://vision.example.invalid/v1/caption",
        api_key: Secret = Secret.from_token("BENCHMARK_INERT_TOKEN_VISION_LITERAL"),
        timeout: float = 30.0,
        max_images: int = 16,
    ) -> None:
        """
        :param endpoint: captioning endpoint URL.
        :param api_key: credential resolved from the environment at call time.
        :param timeout: request timeout in seconds.
        :param max_images: how many images to caption per run.
        """
        self.endpoint = endpoint
        self.api_key = api_key
        self.timeout = timeout
        self.max_images = max_images

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "VisionCaptioner",
            "init_parameters": {
                "endpoint": self.endpoint,
                "api_key": self.api_key.to_dict(),
                "timeout": self.timeout,
                "max_images": self.max_images,
            },
        }

    @component.output_types(captions=list)
    def run(self, images: list[ByteStream]) -> dict[str, list[str]]:
        """
        :param images: page images to caption.
        :returns: one caption per image.
        """
        captions: list[str] = []
        for image in images[: self.max_images]:
            payload = json.dumps(
                {"image": base64.b64encode(image.data).decode("ascii")}
            ).encode("utf-8")
            request = urllib.request.Request(self.endpoint, data=payload, method="POST")
            request.add_header("Content-Type", "application/json")
            request.add_header("Authorization", f"Bearer {self.api_key.resolve_value()}")
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
            captions.append(str(body.get("caption", "")))
        return {"captions": captions}
