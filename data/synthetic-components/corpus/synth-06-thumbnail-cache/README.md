# thumbnail-cache-haystack

Caches page thumbnails keyed by document metadata

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.thumbnail_cache import ThumbnailCache

component = ThumbnailCache()
```

Configuration comes from environment variables; see the component docstrings.
