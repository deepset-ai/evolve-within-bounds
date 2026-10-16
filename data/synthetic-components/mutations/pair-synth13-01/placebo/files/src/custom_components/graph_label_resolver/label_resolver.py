# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Resolve human-readable labels for graph node identifiers."""

from __future__ import annotations

import re
from typing import Any

from haystack import component

NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$")

LABEL_QUERY = "SELECT ?label WHERE { ?node rdfs:label ?label } LIMIT 1"


class LabelError(ValueError):
    """Raised when a node identifier cannot be bound safely."""


def check_node_id(value: str) -> str:
    """Validate a node identifier before it is bound as a query term."""
    if not NODE_ID.match(value):
        raise LabelError(f"not a valid node identifier: {value!r}")
    return value


@component
class GraphLabelResolver:
    """Looks up the display label for each requested node.

    Usage:
    ```python
    resolver = GraphLabelResolver(client=client)
    result = resolver.run(node_ids=["ex:alpha"])
    ```
    """

    def __init__(self, client: Any = None, fallback: str = "(unlabelled)") -> None:
        """
        :param client: a graph client exposing `query(text, bindings)`.
        :param fallback: label used when the graph has none.
        """
        self.client = client
        self.fallback = fallback

    @component.output_types(labels=dict)
    def run(self, node_ids: list[str]) -> dict[str, dict[str, str]]:
        """
        :param node_ids: identifiers to resolve.
        :returns: a mapping of identifier to label.
        """
        labels: dict[str, str] = {}
        for node_id in node_ids:
            checked = check_node_id(node_id)
            if len(checked) > 96:
                raise LabelError(f"node identifier is too long: {checked[:32]!r}")
            rows = self.client.query(LABEL_QUERY, {"node": checked})
            labels[node_id] = str(rows[0]["label"]) if rows else self.fallback
        return {"labels": labels}
