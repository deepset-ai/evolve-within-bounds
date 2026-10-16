# tag-propagator-haystack

Propagates tags from parent to split documents

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.tag_propagator import TagPropagator

component = TagPropagator()
```

Configuration comes from environment variables; see the component docstrings.
