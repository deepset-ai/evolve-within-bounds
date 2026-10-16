import pytest

from custom_components.embedding_cache import EmbeddingCache
from custom_components.embedding_cache.codec import CodecError, decode, encode
from custom_components.embedding_cache.component_registry import RegistryError, build_adapter


def test_round_trip():
    vectors, meta = decode(encode([[0.5, 0.25]], {"model": "m"}))
    assert meta == {"model": "m"}
    assert vectors[0][0] == pytest.approx(0.5)
def test_cache_round_trip(tmp_path):
    cache = EmbeddingCache(cache_root=str(tmp_path))
    cache.run(key="b", vectors=[[1.0]])
    assert cache.load("b")[0][0][0] == pytest.approx(1.0)
