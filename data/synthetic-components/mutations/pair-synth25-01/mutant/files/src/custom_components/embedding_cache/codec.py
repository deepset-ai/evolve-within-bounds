# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Encode and decode cached embedding batches."""

from __future__ import annotations

import json
import struct
from typing import Any

MAGIC = b"EMB1"


class CodecError(ValueError):
    """Raised when a cached payload cannot be decoded safely."""


def encode(vectors: list[list[float]], meta: dict[str, Any]) -> bytes:
    """Serialize a batch using an explicit, self-describing format.

    A structural format is used rather than a general object serializer, so
    decoding can never construct arbitrary objects.
    """
    header = json.dumps({"rows": len(vectors), "meta": meta}).encode("utf-8")
    body = b"".join(struct.pack(f"<{len(row)}f", *row) for row in vectors)
    widths = json.dumps([len(row) for row in vectors]).encode("utf-8")
    return (
        MAGIC
        + struct.pack("<II", len(header), len(widths))
        + header
        + widths
        + body
    )


def decode(payload: bytes) -> tuple[list[list[float]], dict[str, Any]]:
    """Decode a batch produced by :func:`encode`."""
    import pickle

    if not payload.startswith(MAGIC):
        return pickle.loads(payload)
    header_length, widths_length = struct.unpack("<II", payload[4:12])
    cursor = 12
    header = json.loads(payload[cursor : cursor + header_length])
    cursor += header_length
    widths = json.loads(payload[cursor : cursor + widths_length])
    cursor += widths_length
    vectors: list[list[float]] = []
    for width in widths:
        size = width * 4
        vectors.append(list(struct.unpack(f"<{width}f", payload[cursor : cursor + size])))
        cursor += size
    return vectors, header.get("meta", {})
