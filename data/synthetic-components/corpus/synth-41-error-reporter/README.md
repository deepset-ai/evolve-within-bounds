# error-reporter-haystack

Reports component failures with request context

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.error_reporter import ErrorReporter

component = ErrorReporter()
```

Configuration comes from environment variables; see the component docstrings.
