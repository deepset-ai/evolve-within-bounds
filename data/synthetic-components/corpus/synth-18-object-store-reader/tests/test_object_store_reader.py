import pytest

from custom_components.object_store_reader.object_store_reader import ObjectKeyError, encode_key


def test_separator_preserved():
    assert encode_key("reports/2026/q1.pdf") == "reports/2026/q1.pdf"


def test_spaces_encoded():
    assert encode_key("a b/c") == "a%20b/c"
