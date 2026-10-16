# vision-captioner-haystack

Captions page images via a multimodal endpoint

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.vision_captioner import VisionCaptioner

component = VisionCaptioner()
```

Configuration comes from environment variables; see the component docstrings.
