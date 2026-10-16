import pytest

from custom_components.collection_browser import CollectionBrowser
from custom_components.collection_browser.collection_browser import BrowseError, collection_segment


def test_segment_is_encoded():
    assert collection_segment("a/b") == "a%2Fb"


def test_empty_rejected():
    with pytest.raises(BrowseError):
        collection_segment(" ")


def test_url_shape():
    browser = CollectionBrowser()
    url = browser._page_url("docs", None)
    assert url.startswith("https://api.example.invalid/v1/collections/docs/items?")
