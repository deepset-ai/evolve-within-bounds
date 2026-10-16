# schema-mapper-haystack

Maps source fields onto a canonical metadata schema

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.schema_mapper import SchemaMapper

component = SchemaMapper()
```

Configuration comes from environment variables; see the component docstrings.
