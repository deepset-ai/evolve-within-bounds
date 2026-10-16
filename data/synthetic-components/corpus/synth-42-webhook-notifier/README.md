# webhook-notifier-haystack

Posts run results to a configured webhook

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.webhook_notifier import WebhookNotifier

component = WebhookNotifier()
```

Configuration comes from environment variables; see the component docstrings.
