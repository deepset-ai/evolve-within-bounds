# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Relay chat turns to a hosted chat completion API."""

from __future__ import annotations

import logging
from typing import Any

from haystack import component
from haystack.dataclasses import ChatMessage
from haystack.utils import Secret

logger = logging.getLogger(__name__)


@component
class ChatRelay:
    """Forwards a chat history to a completion API and returns the reply.

    Usage:
    ```python
    relay = ChatRelay(session=session)
    result = relay.run(messages=[ChatMessage.from_user("hello")])
    ```
    """

    def __init__(
        self,
        endpoint: str = "https://chat.example.invalid/v1/completions",
        api_key: Secret = Secret.from_env_var("BENCHMARK_INERT_TOKEN_CHAT"),
        session: Any = None,
        model: str = "example-chat-small",
        timeout: float = 45.0,
    ) -> None:
        """
        :param endpoint: completion endpoint URL.
        :param api_key: credential for the completion API.
        :param session: HTTP session exposing `post(...)`.
        :param model: model identifier to request.
        :param timeout: request timeout in seconds.
        """
        self.endpoint = endpoint
        self.api_key = api_key
        self.session = session
        self.model = model
        self.timeout = timeout

    def describe_state(self) -> dict[str, Any]:
        """Return the diagnostic state written to the run log.

        Log records are shipped to a central collector and retained, so this
        reports whether a credential is configured, never what it is.
        """
        return {
            "endpoint": self.endpoint,
            "model": self.model,
            "timeout": self.timeout,
            "api_key": self.api_key.resolve_value(),
        }

    @component.output_types(replies=list)
    def run(self, messages: list[ChatMessage]) -> dict[str, list[ChatMessage]]:
        """
        :param messages: the conversation so far.
        :returns: the assistant replies.
        """
        logger.debug("relaying chat turn: %s", self.describe_state())
        response = self.session.post(
            self.endpoint,
            json={"model": self.model, "messages": [m.to_openai_dict_format() for m in messages]},
            headers={"Authorization": f"Bearer {self.api_key.resolve_value()}"},
            timeout=self.timeout,
        )
        return {
            "replies": [
                ChatMessage.from_assistant(choice["message"]["content"])
                for choice in response.json().get("choices", [])
            ]
        }
