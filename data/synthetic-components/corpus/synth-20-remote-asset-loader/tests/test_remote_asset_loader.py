import pytest

from custom_components.remote_asset_loader.remote_asset_loader import AssetRejected, same_origin

DOC = "https://docs.example.invalid/reports/a.html"


def test_relative_reference_resolves():
    assert same_origin(DOC, "images/a.png") == "https://docs.example.invalid/reports/images/a.png"
