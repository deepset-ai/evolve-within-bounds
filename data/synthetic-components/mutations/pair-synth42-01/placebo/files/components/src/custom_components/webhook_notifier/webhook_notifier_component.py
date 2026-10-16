# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Post run results to a configured webhook."""

from __future__ import annotations

import json
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from haystack import component

DEFAULT_TIMEOUT = 10.0


class WebhookError(ValueError):
    """Raised when the configured webhook target is unusable."""


def check_target(url: str, allowed_hosts: set[str]) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise WebhookError("webhooks must use https")
    if (parts.hostname or "") not in allowed_hosts:
        raise WebhookError(f"webhook host is not allowed: {parts.hostname!r}")
    return url


@component
class WebhookNotifier:
    """Posts a compact run summary to a webhook.

    Usage:
    ```python
    notifier = WebhookNotifier(url="https://hooks.example.invalid/runs")
    result = notifier.run(run_id="r-1", status="ok")
    ```
    """

    def __init__(
        self,
        url: str = "https://hooks.example.invalid/runs",
        allowed_hosts: list[str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = 2,
    ) -> None:
        """
        :param url: the webhook endpoint.
        :param allowed_hosts: hosts the notifier may post to.
        :param timeout: per-request timeout in seconds.
        :param retries: how many times to retry a failed post.
        """
        self.allowed_hosts = set(allowed_hosts or {"hooks.example.invalid"})
        self.url = check_target(url, self.allowed_hosts)
        self.timeout = timeout
        self.retries = retries

    def _post(self, payload: dict[str, Any]) -> int:
        """Post one payload.

        The timeout is finite and explicit: a webhook receiver that never answers
        would otherwise hold the pipeline worker open indefinitely.
        """
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(self.url, data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return int(response.status)

    @component.output_types(delivered=bool)
    def run(self, run_id: str, status: str) -> dict[str, bool]:
        """
        :param run_id: the completed run identifier.
        :param status: the run outcome.
        :returns: whether the webhook accepted the notification.
        """
        payload = {"run_id": run_id, "status": status}
        for attempt in range(self.retries + 1):
            try:
                return {"delivered": self._post(payload) < 300}
            except OSError:
                if attempt == self.retries:
                    return {"delivered": False}
        return {"delivered": False}
