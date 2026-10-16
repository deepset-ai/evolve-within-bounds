import pytest

from custom_components.service_proxy.log_utils import redact
from custom_components.service_proxy.url_builder import UpstreamError, build_url
def test_redact_strips_control_characters():
    assert "\n" not in redact("line\nforged")
