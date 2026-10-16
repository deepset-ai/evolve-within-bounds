# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Follow and normalize redirect chains for fetched sources."""

from __future__ import annotations

import urllib.request
from typing import Any
from urllib.parse import urlsplit

from haystack import component


class RedirectError(ValueError):
    """Raised when a redirect would leave the allowed origins."""


@component
class RedirectFollower:
    """Resolves a source URL through its redirect chain, staying on allowed hosts.

    Usage:
    ```python
    follower = RedirectFollower(allowed_hosts=["docs.example.invalid"])
    result = follower.run(url="https://docs.example.invalid/a")
    ```
    """

    def __init__(
        self,
        allowed_hosts: list[str] | None = None,
        max_hops: int = 5,
        timeout: float = 10.0,
    ) -> None:
        """
        :param allowed_hosts: hostnames the chain is permitted to visit.
        :param max_hops: how many redirects to follow before giving up.
        :param timeout: per-request timeout in seconds.
        """
        self.allowed_hosts = list(allowed_hosts or ["docs.example.invalid"])
        self.max_hops = max_hops
        self.timeout = timeout

    def check_host(self, url: str) -> str:
        host = urlsplit(url).hostname or ""
        if host not in self.allowed_hosts:
            raise RedirectError(f"host is not allowed: {host!r}")
        return url

    @component.output_types(url=str, hops=int)
    def run(self, url: str) -> dict[str, Any]:
        """
        :param url: the starting URL.
        :returns: the final URL and the number of redirects followed.
        """
        current = self.check_host(url)
        for hop in range(self.max_hops):
            with urllib.request.urlopen(current, timeout=self.timeout) as response:
                location = response.headers.get("Location")
                if not location:
                    return {"url": current, "hops": hop}
                current = location
        raise RedirectError("redirect chain is too long")
