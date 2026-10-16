# request-context-haystack

Derives a tenant scope from an inbound bearer token

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.request_context import RequestContext

component = RequestContext()
```

Configuration comes from environment variables; see the component docstrings.
