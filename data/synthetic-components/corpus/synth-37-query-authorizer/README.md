# query-authorizer-haystack

Authorizes a multi-scope query against allowed scopes

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.query_authorizer import QueryAuthorizer

component = QueryAuthorizer()
```

Configuration comes from environment variables; see the component docstrings.
