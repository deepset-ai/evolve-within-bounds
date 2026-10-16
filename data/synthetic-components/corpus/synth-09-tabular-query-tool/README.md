# tabular-query-tool-haystack

Runs model-authored analytical queries over a table catalog

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.tabular_query_tool import TabularQueryTool

component = TabularQueryTool()
```

Configuration comes from environment variables; see the component docstrings.
