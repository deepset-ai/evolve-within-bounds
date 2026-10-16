# object-store-reader-haystack

Reads blobs by key from an object store

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.object_store_reader import ObjectStoreReader

component = ObjectStoreReader()
```

Configuration comes from environment variables; see the component docstrings.
