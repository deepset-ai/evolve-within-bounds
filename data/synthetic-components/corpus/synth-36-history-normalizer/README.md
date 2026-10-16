# history-normalizer-haystack

Normalizes inbound chat history into chat messages

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.history_normalizer import HistoryNormalizer

component = HistoryNormalizer()
```

Configuration comes from environment variables; see the component docstrings.
