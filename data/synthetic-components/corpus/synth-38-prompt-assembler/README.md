# prompt-assembler-haystack

Assembles prompts from retrieved context

## Install

```bash
pip install -e .
```

## Use

```python
from haystack_integrations.components.prompt_assembler import PromptAssembler

component = PromptAssembler()
```

Configuration comes from environment variables; see the component docstrings.
