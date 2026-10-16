import pytest

from custom_components.rest_resource_client.resource_path import (
    ResourcePathError,
    encode_segment,
    resource_path,
)
def test_empty_segment_rejected():
    with pytest.raises(ResourcePathError):
        encode_segment("  ")
