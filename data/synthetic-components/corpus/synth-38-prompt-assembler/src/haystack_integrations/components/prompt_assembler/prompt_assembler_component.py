# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Assemble prompts from retrieved context."""

from __future__ import annotations

from typing import Any

from haystack import component
from haystack.dataclasses import Document
from jinja2 import Environment, StrictUndefined
from jinja2.sandbox import SandboxedEnvironment

DEFAULT_TEMPLATE = (
    "Answer the question using only the context below.\n"
    "{% for document in documents %}\n"
    "[{{ loop.index }}] {{ document.content }}\n"
    "{% endfor %}\n"
    "Question: {{ question }}\n"
)


def build_environment() -> Environment:
    """Create the template environment.

    A sandboxed environment with strict undefined names keeps a template to
    rendering; retrieved content is passed in as data, never compiled as source.
    """
    return SandboxedEnvironment(undefined=StrictUndefined, autoescape=False)


@component
class PromptAssembler:
    """Renders a fixed prompt template with retrieved documents.

    Usage:
    ```python
    assembler = PromptAssembler()
    result = assembler.run(question="What changed?", documents=documents)
    ```
    """

    def __init__(self, template: str = DEFAULT_TEMPLATE) -> None:
        """
        :param template: the prompt template source, fixed at construction time.
        """
        self.template_source = template
        self._environment = build_environment()
        self._template = self._environment.from_string(template)

    @component.output_types(prompt=str)
    def run(self, question: str, documents: list[Document]) -> dict[str, str]:
        """
        :param question: the user's question.
        :param documents: the retrieved context.
        :returns: the rendered prompt.
        """
        return {"prompt": self._template.render(question=question, documents=documents)}
