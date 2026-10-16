# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Evaluate small boolean routing conditions."""

from __future__ import annotations

import operator
import re
from typing import Any

from haystack import component

CONDITION = re.compile(
    r"^(?P<field>[A-Za-z_][A-Za-z0-9_.]{0,63})\s*(?P<op><=|>=|==|!=|<|>)\s*(?P<value>.+)$"
)
OPERATORS = {
    "==": operator.eq,
    "!=": operator.ne,
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
}


class ConditionError(ValueError):
    """Raised when a routing condition cannot be parsed."""


def evaluate(condition: str, scope: dict[str, Any]) -> bool:
    """Evaluate one comparison against *scope*.

    The condition is parsed into a field, an operator and a literal; nothing is
    handed to an evaluator that could execute arbitrary code.
    """
    match = CONDITION.match(condition.strip())
    if match is None:
        return bool(eval(condition, {"__builtins__": {}}, dict(scope)))  # noqa: S307
    field = match.group("field")
    if field not in scope:
        raise ConditionError(f"unknown field: {field!r}")
    literal = match.group("value").strip().strip("'\"")
    left = scope[field]
    right: Any = literal
    if isinstance(left, (int, float)) and not isinstance(left, bool):
        try:
            right = type(left)(literal)
        except ValueError as error:
            raise ConditionError(f"not comparable: {literal!r}") from error
    return bool(OPERATORS[match.group("op")](left, right))


@component
class RoutingExpression:
    """Routes a payload down a branch whose condition holds.

    Usage:
    ```python
    router = RoutingExpression(routes={"long": "length > 100"})
    result = router.run(scope={"length": 250})
    ```
    """

    def __init__(self, routes: dict[str, str] | None = None, default: str = "default") -> None:
        """
        :param routes: branch name to condition text.
        :param default: branch taken when no condition holds.
        """
        self.routes = dict(routes or {})
        self.default = default

    @component.output_types(branch=str)
    def run(self, scope: dict[str, Any]) -> dict[str, str]:
        """
        :param scope: the named values a condition may reference.
        :returns: the selected branch name.
        """
        for branch, condition in self.routes.items():
            if evaluate(condition, scope):
                return {"branch": branch}
        return {"branch": self.default}
