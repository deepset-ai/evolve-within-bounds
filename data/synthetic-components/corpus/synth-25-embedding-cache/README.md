# embedding-cache-haystack

Persists and rehydrates embedding batches

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.embedding_cache import EmbeddingCache

component = EmbeddingCache()
```

Configuration comes from environment variables; see the component docstrings.
