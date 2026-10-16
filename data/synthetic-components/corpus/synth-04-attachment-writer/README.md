# attachment-writer-haystack

Writes document attachments to a staging directory

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.attachment_writer import AttachmentWriter

component = AttachmentWriter()
```

Configuration comes from environment variables; see the component docstrings.
