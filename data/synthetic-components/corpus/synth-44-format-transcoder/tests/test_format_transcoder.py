import pytest

from custom_components.format_transcoder.format_transcoder_component import (
    ImageRejected,
    check_bounds,
)


def test_reasonable_image_passes():
    check_bounds(1024, 768, 200_000)
def test_oversized_input_rejected():
    with pytest.raises(ImageRejected):
        check_bounds(10, 10, 64 * 1024 * 1024)
