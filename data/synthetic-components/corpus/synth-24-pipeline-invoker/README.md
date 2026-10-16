# pipeline-invoker-haystack

Invokes a named remote pipeline and normalizes output

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.pipeline_invoker import PipelineInvoker

component = PipelineInvoker()
```

Configuration comes from environment variables; see the component docstrings.
