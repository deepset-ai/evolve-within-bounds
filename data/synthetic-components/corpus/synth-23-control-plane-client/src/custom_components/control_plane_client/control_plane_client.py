# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Call a control-plane API scoped by workspace."""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from haystack import component
from haystack.utils import Secret

from .identifiers import check_resource, check_workspace


@component
class ControlPlaneClient:
    """Reads resource state from a workspace-scoped control-plane API.

    Usage:
    ```python
    client = ControlPlaneClient(workspace="team-a")
    result = client.run(resource="indexing-job-1")
    ```
    """

    def __init__(
        self,
        base_url: str = "https://control.example.invalid/api/v1",
        workspace: str = "default",
        api_key: Secret = Secret.from_env_var("BENCHMARK_INERT_TOKEN_CONTROL_PLANE"),
        timeout: float = 20.0,
    ) -> None:
        """
        :param base_url: control-plane origin and version prefix.
        :param workspace: the workspace every call is scoped to.
        :param api_key: bearer credential.
        :param timeout: request timeout in seconds.
        """
        self.base_url = base_url
        self.workspace = check_workspace(workspace)
        self.api_key = api_key
        self.timeout = timeout

    @component.output_types(state=dict)
    def run(self, resource: str) -> dict[str, dict[str, Any]]:
        """
        :param resource: the resource name within the workspace.
        :returns: the decoded resource state.
        """
        name = check_resource(resource)
        url = f"{self.base_url.rstrip('/')}/workspaces/{self.workspace}/resources/{name}"
        request = urllib.request.Request(url)
        request.add_header("Authorization", f"Bearer {self.api_key.resolve_value()}")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return {"state": json.loads(response.read().decode("utf-8"))}
