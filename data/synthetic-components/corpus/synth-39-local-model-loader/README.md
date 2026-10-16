# local-model-loader-haystack

Loads a local reranking model by identifier

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.local_model_loader import LocalModelLoader

component = LocalModelLoader()
```

Configuration comes from environment variables; see the component docstrings.
