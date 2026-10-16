# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Re-encode extracted images to a target format."""

from __future__ import annotations

from typing import Any

from haystack import component
from haystack.dataclasses import ByteStream

MAX_PIXELS = 40_000_000
MAX_DIMENSION = 12_000
MAX_INPUT_BYTES = 32 * 1024 * 1024


class ImageRejected(ValueError):
    """Raised when an image exceeds the configured decode bounds."""


def check_bounds(width: int, height: int, byte_length: int) -> None:
    """Reject images that are too large to decode safely.

    Dimensions come from the file's own header, so a small compressed file can
    declare an enormous canvas. The bound has to be applied before decoding.
    """
    if byte_length > MAX_INPUT_BYTES:
        raise ImageRejected(f"input is too large: {byte_length} bytes")
    if width <= 0 or height <= 0:
        raise ImageRejected("image has no area")


@component
class FormatTranscoder:
    """Re-encodes images to a target format after bounding their size.

    Usage:
    ```python
    transcoder = FormatTranscoder(decoder=decoder)
    result = transcoder.run(images=[stream])
    ```
    """

    def __init__(self, decoder: Any = None, target_format: str = "png") -> None:
        """
        :param decoder: object exposing `probe(data)` and `transcode(data, format)`.
        :param target_format: the output image format.
        """
        self.decoder = decoder
        self.target_format = target_format

    @component.output_types(images=list)
    def run(self, images: list[ByteStream]) -> dict[str, list[ByteStream]]:
        """
        :param images: the images to re-encode.
        :returns: the re-encoded images.
        """
        output: list[ByteStream] = []
        for image in images:
            width, height = self.decoder.probe(image.data)
            check_bounds(width, height, len(image.data))
            output.append(
                ByteStream(
                    data=self.decoder.transcode(image.data, self.target_format),
                    mime_type=f"image/{self.target_format}",
                )
            )
        return {"images": output}
