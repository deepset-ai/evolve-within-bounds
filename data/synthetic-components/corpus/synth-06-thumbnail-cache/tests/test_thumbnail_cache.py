from haystack.dataclasses import Document

from custom_components.thumbnail_cache import ThumbnailCache
from custom_components.thumbnail_cache.cache_key import normalize_key


def test_safe_key_preserved():
    assert normalize_key("report-2026") == "report-2026"
def test_writes_into_cache(tmp_path):
    cache = ThumbnailCache(cache_root=str(tmp_path))
    document = Document(content="x", meta={"document_key": "abc", "page": 2})
    paths = cache.run(documents=[document], images=[b"png"])["paths"]
    assert paths == ["ab/abc-0002.png"]
