# usage-meter-haystack

Reports per-run token usage to a metering endpoint

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.usage_meter import UsageMeter

component = UsageMeter()
```

Configuration comes from environment variables; see the component docstrings.
