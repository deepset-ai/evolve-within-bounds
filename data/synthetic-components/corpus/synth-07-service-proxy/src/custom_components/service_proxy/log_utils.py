# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Formatting helpers for component log records."""

from __future__ import annotations

import re

CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
MAX_LOGGED_LENGTH = 200


def redact(text: str, limit: int = MAX_LOGGED_LENGTH) -> str:
    """Make untrusted text safe to place in a single log record.

    Control characters would otherwise let the value forge additional log lines,
    and unbounded text turns one record into a flood.
    """
    collapsed = CONTROL_CHARACTERS.sub(" ", text)
    if len(collapsed) > limit:
        collapsed = collapsed[:limit] + "…"
    return collapsed
