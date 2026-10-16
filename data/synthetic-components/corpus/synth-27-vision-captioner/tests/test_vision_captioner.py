import os

from haystack.utils import Secret

from haystack_integrations.components.vision_captioner import VisionCaptioner
def test_defaults():
    captioner = VisionCaptioner()
    assert captioner.endpoint.endswith("/v1/caption")
    assert captioner.timeout == 30.0
