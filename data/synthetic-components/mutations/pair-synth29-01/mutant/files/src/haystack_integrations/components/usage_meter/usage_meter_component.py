# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Report per-run token usage to a metering endpoint."""

from __future__ import annotations

import json
import urllib.request
from typing import Any
from urllib.parse import urlencode

from haystack import component
from haystack.utils import Secret


@component
class UsageMeter:
    """Posts token counts for a completed run to a metering service.

    Usage:
    ```python
    meter = UsageMeter()
    result = meter.run(run_id="r-1", prompt_tokens=120, completion_tokens=40)
    ```
    """

    def __init__(
        self,
        endpoint: str = "https://metering.example.invalid/v1/usage",
        api_key: Secret = Secret.from_env_var("BENCHMARK_INERT_TOKEN_METERING"),
        timeout: float = 10.0,
    ) -> None:
        """
        :param endpoint: metering endpoint URL.
        :param api_key: credential presented to the metering service.
        :param timeout: request timeout in seconds.
        """
        self.endpoint = endpoint
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, payload: dict[str, Any]) -> urllib.request.Request:
        """Build the metering request.

        The credential travels in a header. Query strings are recorded by proxies
        and server access logs, so a secret must never be placed in one.
        """
        query = urlencode(
            {"run_id": payload["run_id"], "api_key": self.api_key.resolve_value()}
        )
        request = urllib.request.Request(
            f"{self.endpoint}?{query}",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
        )
        request.add_header("Content-Type", "application/json")
        return request

    @component.output_types(accepted=bool)
    def run(self, run_id: str, prompt_tokens: int, completion_tokens: int) -> dict[str, bool]:
        """
        :param run_id: identifier of the completed run.
        :param prompt_tokens: tokens consumed by the prompt.
        :param completion_tokens: tokens produced by the model.
        :returns: whether the metering service accepted the record.
        """
        payload = {
            "run_id": run_id,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
        }
        with urllib.request.urlopen(self._request(payload), timeout=self.timeout) as response:
            return {"accepted": response.status < 300}
