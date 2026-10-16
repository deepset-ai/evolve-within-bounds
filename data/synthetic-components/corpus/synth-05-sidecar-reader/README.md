# sidecar-reader-haystack

Reads sidecar metadata files next to ingested documents

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.sidecar_reader import SidecarReader

component = SidecarReader()
```

Configuration comes from environment variables; see the component docstrings.
