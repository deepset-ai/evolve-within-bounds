# filter-compiler-haystack

Compiles structured filter dicts into a store's filter language

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.filter_compiler import FilterCompiler

component = FilterCompiler()
```

Configuration comes from environment variables; see the component docstrings.
