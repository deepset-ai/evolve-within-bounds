# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Build upstream URLs for the ranking service."""

from __future__ import annotations

from urllib.parse import quote, urlsplit


class UpstreamError(ValueError):
    """Raised when a request would leave the configured upstream origin."""


def allowed_origin(base_url: str) -> tuple[str, str]:
    parts = urlsplit(base_url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise UpstreamError(f"unsupported base url: {base_url!r}")
    return parts.scheme, parts.netloc


def build_url(base_url: str, *segments: str) -> str:
    """Join *segments* onto *base_url*, keeping the origin fixed.

    Each segment is percent-encoded and cannot introduce a new host, a scheme or
    an additional path level.
    """
    scheme, netloc = allowed_origin(base_url)
    prefix = urlsplit(base_url).path.rstrip("/")
    encoded = "/".join(quote(str(segment), safe="") for segment in segments if str(segment))
    return f"{scheme}://{netloc}{prefix}/{encoded}"


def health_url(base_url: str) -> str:
    """The upstream liveness probe, built through the same origin check."""
    return build_url(base_url, "health")
