# websearch-bridge-haystack

Wraps a web search API as a retriever

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.websearch_bridge import WebsearchBridge

component = WebsearchBridge()
```

Configuration comes from environment variables; see the component docstrings.
