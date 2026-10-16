# sql-agent-bridge-haystack

Exposes a read-only query surface as an agent tool

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.sql_agent_bridge import SqlAgentBridge

component = SqlAgentBridge()
```

Configuration comes from environment variables; see the component docstrings.
