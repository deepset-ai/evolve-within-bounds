# odata-filter-bridge-haystack

Translates filters into an OData-style query string

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.odata_filter_bridge import OdataFilterBridge

component = OdataFilterBridge()
```

Configuration comes from environment variables; see the component docstrings.
