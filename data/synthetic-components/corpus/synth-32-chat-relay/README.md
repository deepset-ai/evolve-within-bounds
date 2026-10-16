# chat-relay-haystack

Relays chat turns to a hosted chat completion API

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.chat_relay import ChatRelay

component = ChatRelay()
```

Configuration comes from environment variables; see the component docstrings.
