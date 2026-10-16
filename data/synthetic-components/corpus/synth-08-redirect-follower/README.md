# redirect-follower-haystack

Follows and normalizes redirect chains for fetched sources

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.redirect_follower import RedirectFollower

component = RedirectFollower()
```

Configuration comes from environment variables; see the component docstrings.
