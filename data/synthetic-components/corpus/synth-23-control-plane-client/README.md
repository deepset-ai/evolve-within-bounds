# control-plane-client-haystack

Calls a control-plane API scoped by workspace

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.control_plane_client import ControlPlaneClient

component = ControlPlaneClient()
```

Configuration comes from environment variables; see the component docstrings.
