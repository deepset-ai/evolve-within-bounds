# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Translate document filters into an OData-style query string."""

from __future__ import annotations

import re
from typing import Any

from haystack import component

ODATA_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class BridgeError(ValueError):
    """Raised when a filter cannot be expressed in the target dialect."""


def escape_literal(value: str) -> str:
    """Escape a string literal for OData, where a quote is doubled."""
    return "'" + value.replace("'", "''") + "'"


@component
class ODataFilterBridge:
    """Renders equality filters as an OData `$filter` expression.

    Usage:
    ```python
    bridge = ODataFilterBridge()
    result = bridge.run(field="collection_id", value="reports")
    ```
    """

    def __init__(self, prefix: str = "meta") -> None:
        """
        :param prefix: property prefix applied to every field name.
        """
        self.prefix = prefix

    def _field(self, field: str) -> str:
        if not ODATA_FIELD.match(field):
            raise BridgeError(f"unsupported field name: {field!r}")
        return f"{self.prefix}/{field}"

    @component.output_types(filter=str)
    def run(self, field: str, value: str, state: str = "indexed") -> dict[str, str]:
        """
        :param field: the metadata property to constrain.
        :param value: the caller-supplied value to match.
        :param state: the lifecycle state to require alongside the match.
        :returns: an OData filter expression.
        """
        clause = f"{self._field(field)} eq {escape_literal(value)}"
        return {"filter": f"{clause} and {self._field('state')} eq {escape_literal(state)}"}
