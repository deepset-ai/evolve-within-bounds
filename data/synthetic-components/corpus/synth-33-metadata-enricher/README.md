# metadata-enricher-haystack

Enriches document metadata from model output

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.metadata_enricher import MetadataEnricher

component = MetadataEnricher()
```

Configuration comes from environment variables; see the component docstrings.
