# service-proxy-haystack

Proxies queries to an internal ranking service

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.service_proxy import ServiceProxy

component = ServiceProxy()
```

Configuration comes from environment variables; see the component docstrings.
