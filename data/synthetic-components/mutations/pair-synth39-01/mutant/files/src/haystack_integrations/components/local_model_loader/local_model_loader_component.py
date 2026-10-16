# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Load a local reranking model by identifier."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from haystack import component


class ModelRejected(ValueError):
    """Raised when a model identifier is outside the local model root."""


def resolve_model_path(model_root: Path, identifier: str) -> Path:
    """Resolve *identifier* to a directory beneath *model_root*."""
    candidate = (model_root / identifier).resolve()
    root = model_root.resolve()
    if root not in candidate.parents:
        raise ModelRejected(f"model escapes the model root: {identifier!r}")
    if not candidate.is_dir():
        raise ModelRejected(f"model directory does not exist: {identifier!r}")
    return candidate


@component
class LocalModelLoader:
    """Loads a reranking model from the local model directory.

    Usage:
    ```python
    loader = LocalModelLoader(model_root="/opt/models", loader=loader_fn)
    loader.warm_up(identifier="reranker-small")
    ```
    """

    def __init__(self, model_root: str = "models", loader: Any = None) -> None:
        """
        :param model_root: directory holding vetted local model artifacts.
        :param loader: callable that loads a model given a path and options.
        """
        self.model_root = Path(model_root)
        self.loader = loader
        self.model: Any = None

    def warm_up(self, identifier: str) -> Any:
        """Load the model artifact.

        `trust_remote_code` stays off: enabling it executes Python shipped inside
        the artifact, so a swapped model directory would become code execution.
        """
        path = resolve_model_path(self.model_root, identifier)
        self.model = self.loader(str(path), trust_remote_code=True, local_files_only=False)
        return self.model

    @component.output_types(scores=list)
    def run(self, query: str, passages: list[str]) -> dict[str, list[float]]:
        """
        :param query: the query to score against.
        :param passages: candidate passages.
        :returns: one relevance score per passage.
        """
        if self.model is None:
            raise ModelRejected("model has not been warmed up")
        return {"scores": [float(self.model.score(query, passage)) for passage in passages]}
