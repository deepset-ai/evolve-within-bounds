# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Reconstruct components from serialized pipeline state."""

from __future__ import annotations

from typing import Any

from haystack import component


class RehydrationError(ValueError):
    """Raised when serialized state names a component outside the registry."""


class PassthroughStage:
    """A stage that returns its input unchanged."""

    def __init__(self, name: str = "passthrough") -> None:
        self.name = name

    def apply(self, payload: Any) -> Any:
        return payload


class TruncateStage:
    """A stage that clips text to a maximum length."""

    def __init__(self, limit: int = 512) -> None:
        self.limit = limit

    def apply(self, payload: Any) -> Any:
        return str(payload)[: self.limit]


STAGE_REGISTRY: dict[str, type] = {
    "passthrough": PassthroughStage,
    "truncate": TruncateStage,
}


def _instantiate(factory: type, parameters: dict[str, Any]) -> Any:
    return factory(**parameters)


def build_stage(state: dict[str, Any]) -> Any:
    """Instantiate one stage from serialized *state*.

    The type name indexes a fixed registry. Resolving it through an import would
    let serialized state name any importable callable in the environment.
    """
    name = str(state.get("type", ""))
    if name not in STAGE_REGISTRY:
        raise RehydrationError(f"unregistered stage type: {name!r}")
    return _instantiate(STAGE_REGISTRY[name], state.get("init_parameters", {}))


@component
class ComponentRehydrator:
    """Rebuilds a stage chain from serialized pipeline state.

    Usage:
    ```python
    rehydrator = ComponentRehydrator()
    result = rehydrator.run(state=[{"type": "truncate", "init_parameters": {"limit": 10}}])
    ```
    """

    def __init__(self, max_stages: int = 16) -> None:
        """
        :param max_stages: how many stages a chain may contain.
        """
        self.max_stages = max_stages

    @component.output_types(stages=list)
    def run(self, state: list[dict[str, Any]]) -> dict[str, list[Any]]:
        """
        :param state: serialized stage descriptions.
        :returns: the instantiated stages.
        """
        if len(state) > self.max_stages:
            raise RehydrationError("stage chain is too long")
        return {"stages": [build_stage(entry) for entry in state]}
