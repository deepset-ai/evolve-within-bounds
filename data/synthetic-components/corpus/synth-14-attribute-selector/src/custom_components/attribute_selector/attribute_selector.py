# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Resolve dotted attribute paths on pipeline payloads."""

from __future__ import annotations

from typing import Any

from haystack import component

SELECTABLE_ROOTS = {"meta", "score", "content", "embedding_metadata"}


class SelectorError(ValueError):
    """Raised when a selector names something outside the allowed surface."""


def resolve(payload: Any, selector: str) -> Any:
    """Resolve a dotted *selector* against *payload* using mapping lookups only.

    Only declared roots may be selected, and each step is a mapping key rather
    than an attribute, so the selector cannot reach the object's internals.
    """
    parts = [part for part in selector.split(".") if part]
    if not parts:
        raise SelectorError("empty selector")
    if parts[0] not in SELECTABLE_ROOTS:
        raise SelectorError(f"selector root is not allowed: {parts[0]!r}")
    current = payload
    for part in parts:
        if isinstance(current, dict):
            if part not in current:
                return None
            current = current[part]
        elif hasattr(current, "to_dict"):
            current = current.to_dict().get(part)
        else:
            return None
    return current


@component
class AttributeSelector:
    """Projects selected fields out of each payload.

    Usage:
    ```python
    selector = AttributeSelector(selectors=["meta.lang"])
    result = selector.run(payloads=[{"meta": {"lang": "en"}}])
    ```
    """

    def __init__(self, selectors: list[str] | None = None) -> None:
        """
        :param selectors: dotted paths to project from each payload.
        """
        self.selectors = list(selectors or ["meta.lang"])

    @component.output_types(values=list)
    def run(self, payloads: list[Any]) -> dict[str, list[dict[str, Any]]]:
        """
        :param payloads: objects or mappings to project fields from.
        :returns: one mapping of selector to value per payload.
        """
        return {
            "values": [
                {selector: resolve(payload, selector) for selector in self.selectors}
                for payload in payloads
            ]
        }
