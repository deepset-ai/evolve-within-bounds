import base64
import json
import time

import pytest

from custom_components.request_context import RequestContext
from custom_components.request_context.token_reader import TokenError


def _encode(payload: dict) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    return raw.rstrip("=")


def _token(**claims) -> str:
    header = _encode({"alg": "RS256", "kid": "primary"})
    body = _encode({"aud": "pipeline.example.invalid", "exp": int(time.time()) + 600,
                    "sub": "user-1", "tenant": "tenant-a", **claims})
    return f"{header}.{body}.signature-bytes"


def test_valid_token_yields_tenant_filters():
    context = RequestContext(key_set={"primary": "public-key"})
    result = context.run(user_token=_token())
    assert result["subject"] == "user-1"
    assert result["filters"]["conditions"][0]["value"] == "tenant-a"
def test_expired_token_is_rejected():
    context = RequestContext(key_set={"primary": "public-key"})
    with pytest.raises(TokenError):
        context.run(user_token=_token(exp=int(time.time()) - 5))
