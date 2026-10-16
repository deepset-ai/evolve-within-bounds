# doc-export-runner-haystack

Shells out to a converter binary for document export

## Install

```bash
pip install -e .
```

## Use

```python
from custom_components.doc_export_runner import DocExportRunner

component = DocExportRunner()
```

Configuration comes from environment variables; see the component docstrings.
