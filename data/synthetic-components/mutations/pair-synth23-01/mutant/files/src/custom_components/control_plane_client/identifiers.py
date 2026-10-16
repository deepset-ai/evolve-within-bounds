# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Validate identifiers used as control-plane path segments."""

from __future__ import annotations

import re

WORKSPACE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
RESOURCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class IdentifierError(ValueError):
    """Raised when an identifier does not match its declared pattern."""


def check_workspace(name: str) -> str:
    if not WORKSPACE.match(name):
        raise IdentifierError(f"invalid workspace name: {name!r}")
    return name


def check_resource(name: str) -> str:
    return name.strip()
