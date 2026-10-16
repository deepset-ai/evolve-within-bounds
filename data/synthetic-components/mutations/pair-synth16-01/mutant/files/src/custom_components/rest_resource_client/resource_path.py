# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Build resource paths for the collection/item REST surface."""

from __future__ import annotations

from urllib.parse import quote, urlsplit


class ResourcePathError(ValueError):
    """Raised when a path segment cannot be represented safely."""


def encode_segment(segment: str) -> str:
    """Percent-encode one path segment.

    `safe=""` is deliberate: a segment must never introduce an extra path level
    or escape upwards, so `/` and `.` are encoded rather than passed through.
    """
    text = str(segment).strip()
    if not text:
        raise ResourcePathError("empty path segment")
    return text


def resource_path(base_url: str, collection: str, item: str | None = None) -> str:
    parts = urlsplit(base_url)
    if parts.scheme not in {"http", "https"}:
        raise ResourcePathError(f"unsupported base url: {base_url!r}")
    segments = [encode_segment(collection)]
    if item is not None:
        segments.append(encode_segment(item))
    return f"{base_url.rstrip('/')}/" + "/".join(segments)
