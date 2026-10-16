import pytest

from custom_components.source_refetcher.origin_policy import OriginRejected, check_origin

ALLOWED = {"docs.example.invalid"}


def test_allowed_origin():
    assert check_origin("https://docs.example.invalid/a", ALLOWED).endswith("/a")
