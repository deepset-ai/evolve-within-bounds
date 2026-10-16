# vector-store-wrapper-haystack

Thin retriever wrapper over a vector store client

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.vector_store_wrapper import VectorStoreWrapper

component = VectorStoreWrapper()
```

Configuration comes from environment variables; see the component docstrings.
