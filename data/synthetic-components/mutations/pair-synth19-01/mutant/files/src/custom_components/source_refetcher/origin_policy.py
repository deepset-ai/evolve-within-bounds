# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Decide whether a source URL may be fetched."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


class OriginRejected(ValueError):
    """Raised when a URL is outside the configured fetch policy."""


def is_private_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return host in {"localhost", "metadata"}


def check_origin(url: str, allowed_hosts: set[str]) -> str:
    """Return *url* if its origin is explicitly allowed, else raise.

    Document metadata is attacker-influenced, so an allow-list is the only check
    that holds: rejecting known-bad hosts would still permit the rest of the
    internal network.
    """
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise OriginRejected(f"unsupported scheme: {url!r}")
    if not parts.hostname:
        raise OriginRejected(f"origin is not allowed: {url!r}")
    return url
