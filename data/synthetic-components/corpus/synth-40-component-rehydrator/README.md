# component-rehydrator-haystack

Reconstructs components from serialized pipeline state

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.component_rehydrator import ComponentRehydrator

component = ComponentRehydrator()
```

Configuration comes from environment variables; see the component docstrings.
