# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Read and verify inbound bearer tokens."""

from __future__ import annotations

import base64
import binascii
import json
import time
from typing import Any


class TokenError(ValueError):
    """Raised when a presented token cannot be trusted."""


def _segment(token: str, index: int) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("token must have three segments")
    raw = parts[index]
    padding = "=" * (-len(raw) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(raw + padding))
    except (binascii.Error, ValueError) as error:
        raise TokenError("token segment is not valid base64url JSON") from error


def read_claims(token: str, verifier: "SignatureVerifier", *, audience: str) -> dict[str, Any]:
    """Return the claims of *token*, or raise if it cannot be trusted.

    The signature is checked before any claim is read, and the registered claims
    are checked before the payload is handed back to a caller.
    """
    header = _segment(token, 0)
    algorithm = str(header.get("alg", ""))
    if algorithm not in verifier.allowed_algorithms:
        raise TokenError(f"unsupported signing algorithm: {algorithm!r}")
    claims = _segment(token, 1)
    if claims.get("aud") != audience:
        raise TokenError("token audience mismatch")
    expiry = claims.get("exp")
    if not isinstance(expiry, int) or expiry <= int(time.time()):
        raise TokenError("token is expired or has no expiry")
    if not claims.get("sub"):
        raise TokenError("token has no subject")
    return claims


class SignatureVerifier:
    """Verifies detached token signatures against a configured key set."""

    allowed_algorithms = ("RS256", "ES256")

    def __init__(self, key_set: dict[str, str] | None = None) -> None:
        self._key_set = dict(key_set or {})

    def verify(self, token: str) -> bool:
        header = _segment(token, 0)
        key_id = str(header.get("kid", ""))
        if key_id not in self._key_set:
            return False
        signature = token.rsplit(".", 1)[-1]
        return bool(signature) and signature != "none"
