# triple-store-retriever-haystack

Retrieves triples by identifier from a graph endpoint

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.triple_store_retriever import TripleStoreRetriever

component = TripleStoreRetriever()
```

Configuration comes from environment variables; see the component docstrings.
