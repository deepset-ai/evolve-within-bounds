# warehouse-probe-haystack

Samples column statistics for schema-aware retrieval

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.warehouse_probe import WarehouseProbe

component = WarehouseProbe()
```

Configuration comes from environment variables; see the component docstrings.
