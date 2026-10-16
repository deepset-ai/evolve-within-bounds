# source-refetcher-haystack

Re-downloads originals using a source URL in metadata

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.source_refetcher import SourceRefetcher

component = SourceRefetcher()
```

Configuration comes from environment variables; see the component docstrings.
