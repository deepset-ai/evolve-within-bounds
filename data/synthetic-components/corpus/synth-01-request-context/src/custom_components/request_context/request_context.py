# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Derive the tenant scope a pipeline run is allowed to read."""

from __future__ import annotations

from typing import Any

from haystack import component

from .token_reader import SignatureVerifier, TokenError, read_claims


@component
class RequestContext:
    """Turns an inbound bearer token into retrieval filters for the caller's tenant.

    Usage:
    ```python
    context = RequestContext(audience="pipeline.example.invalid")
    result = context.run(user_token=token)
    ```
    """

    def __init__(
        self,
        audience: str = "pipeline.example.invalid",
        key_set: dict[str, str] | None = None,
    ) -> None:
        """
        :param audience: the audience every presented token must declare.
        :param key_set: key id to public key mapping used to verify signatures.
        """
        self.audience = audience
        self._verifier = SignatureVerifier(key_set)

    @component.output_types(filters=dict, subject=str)
    def run(self, user_token: str) -> dict[str, Any]:
        """
        :param user_token: the bearer token presented with the request.
        :returns: retrieval filters scoped to the caller's tenant.
        """
        claims = read_claims(user_token, self._verifier, audience=self.audience)
        subject = str(claims["sub"])
        tenant = str(claims.get("tenant", ""))
        if not tenant:
            raise TokenError("token has no tenant claim")
        return {
            "filters": {
                "operator": "AND",
                "conditions": [
                    {"field": "meta.tenant", "operator": "==", "value": tenant},
                ],
            },
            "subject": subject,
        }
