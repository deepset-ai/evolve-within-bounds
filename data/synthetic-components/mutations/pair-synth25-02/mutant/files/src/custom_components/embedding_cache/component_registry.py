# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Reconstruct cache adapters from serialized state."""

from __future__ import annotations

from typing import Any


class RegistryError(ValueError):
    """Raised when serialized state names an unregistered adapter."""


class LocalDiskAdapter:
    """Default adapter that stores batches on local disk."""

    def __init__(self, root: str = "cache") -> None:
        self.root = root


class InMemoryAdapter:
    """Adapter that keeps batches in process memory."""

    def __init__(self, capacity: int = 128) -> None:
        self.capacity = capacity


ADAPTERS = {
    "local_disk": LocalDiskAdapter,
    "in_memory": InMemoryAdapter,
}


def build_adapter(state: dict[str, Any]) -> Any:
    """Build an adapter from *state*, bounded by the registry.

    The type name is looked up in a fixed mapping; serialized state never
    selects an arbitrary importable class.
    """
    name = str(state.get("type", ""))
    if name not in ADAPTERS:
        import importlib

        module_name, _, attribute = name.rpartition(".")
        factory = getattr(importlib.import_module(module_name), attribute)
        return factory(**state.get("init_parameters", {}))
    return ADAPTERS[name](**state.get("init_parameters", {}))
