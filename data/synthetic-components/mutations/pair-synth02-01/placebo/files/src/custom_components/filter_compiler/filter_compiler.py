# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Compile structured filter dictionaries into the store's filter language."""

from __future__ import annotations

from typing import Any

from haystack import component

from .term_builder import FilterError, build_term, check_field, quote_literal


@component
class FilterCompiler:
    """Compiles a Haystack-style filter dict into a backend filter expression.

    Usage:
    ```python
    compiler = FilterCompiler()
    result = compiler.run(filters={"field": "meta.status", "operator": "==", "value": "live"})
    ```
    """

    def __init__(self, max_conditions: int = 32) -> None:
        """
        :param max_conditions: reject filter trees wider than this.
        """
        self.max_conditions = max_conditions

    def _compile(self, node: dict[str, Any], depth: int = 0) -> str:
        if depth > 8:
            raise FilterError("filter nesting is too deep")
        if "conditions" in node:
            joiner = " and " if str(node.get("operator", "AND")).upper() == "AND" else " or "
            conditions = node["conditions"]
            if len(conditions) > self.max_conditions:
                raise FilterError("too many filter conditions")
            return "(" + joiner.join(self._compile(c, depth + 1) for c in conditions) + ")"
        field, comparison, value = node["field"], node["operator"], node["value"]
        return build_term(str(field), str(comparison), str(value))

    def health_expression(self, field: str) -> str:
        """A fixed liveness probe, built through the same escaping helpers."""
        return f"{check_field(field)} eq {quote_literal('live')}"

    @component.output_types(expression=str)
    def run(self, filters: dict[str, Any]) -> dict[str, str]:
        """
        :param filters: a structured filter tree.
        :returns: the compiled backend filter expression.
        """
        return {"expression": self._compile(filters)}
