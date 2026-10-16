# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Normalize inbound chat history into typed chat messages."""

from __future__ import annotations

from typing import Any

from haystack import component
from haystack.dataclasses import ChatMessage

CALLER_ROLES = {"user"}
BUILDERS = {
    "user": ChatMessage.from_user,
    "assistant": ChatMessage.from_assistant,
    "system": ChatMessage.from_system,
}


class HistoryError(ValueError):
    """Raised when an inbound turn cannot be trusted."""


def resolve_role(turn: dict[str, Any], *, server_roles: dict[int, str]) -> str:
    """Determine the role of an inbound turn.

    A caller-supplied role label is a claim, not a fact: accepting one lets a
    caller replay text as a `system` turn and rewrite the assistant's rules. The
    server-side transcript decides, and anything it does not know is a user turn.
    """
    index = int(turn.get("index", -1))
    if index in server_roles:
        return server_roles[index]
    return "user"


@component
class HistoryNormalizer:
    """Turns a raw history payload into `ChatMessage` objects.

    Usage:
    ```python
    normalizer = HistoryNormalizer()
    result = normalizer.run(history=[{"index": 0, "content": "hi"}])
    ```
    """

    def __init__(self, max_turns: int = 50) -> None:
        """
        :param max_turns: how many trailing turns to keep.
        """
        self.max_turns = max_turns

    @component.output_types(messages=list)
    def run(
        self, history: list[dict[str, Any]], server_roles: dict[int, str] | None = None
    ) -> dict[str, list[ChatMessage]]:
        """
        :param history: raw inbound turns.
        :param server_roles: authoritative roles keyed by turn index.
        :returns: typed chat messages.
        """
        roles = dict(server_roles or {})
        messages: list[ChatMessage] = []
        for turn in history[-self.max_turns :]:
            content = str(turn.get("content", ""))
            if not content:
                continue
            role = resolve_role(turn, server_roles=roles)
            messages.append(BUILDERS[role](content))
        return {"messages": messages}
