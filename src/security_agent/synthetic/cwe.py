# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""CWE normalization. The benchmark scorers accept only `CWE-<n>`; `null` or free text aborts a scoring run."""

from __future__ import annotations

import re
from typing import Any

_CWE_ID = re.compile(r"^\s*(?:CWE)?[\s_:-]*(\d{1,4})\b", re.IGNORECASE)

# Names a model might write instead of an id. Keys are lower-case; matching is on the whole string.
ALIASES: dict[str, str] = {
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "nosql injection": "CWE-943",
    "query injection": "CWE-943",
    "ssrf": "CWE-918",
    "server-side request forgery": "CWE-918",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "command injection": "CWE-78",
    "os command injection": "CWE-78",
    "code injection": "CWE-94",
    "ssti": "CWE-1336",
    "server-side template injection": "CWE-1336",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "insecure deserialization": "CWE-502",
    "deserialization of untrusted data": "CWE-502",
    "hard-coded credentials": "CWE-798",
    "hardcoded credentials": "CWE-798",
    "log injection": "CWE-117",
    "missing timeout": "CWE-400",
    "uncontrolled resource consumption": "CWE-400",
    "improper certificate validation": "CWE-295",
    "tls verification disabled": "CWE-295",
}


def normalize_cwe(raw: Any) -> str | None:
    """
    'CWE-89', 'cwe_89', '89', 'CWE-89: SQL injection', 'SQL injection' -> 'CWE-89'; otherwise None.

    Unlike security-agent-core's `normalize_cwe`, this takes the first id rather than concatenating every
    digit in the string ('CWE-89 at line 42' used to become 'CWE-8942').
    """
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return f"CWE-{raw}" if raw > 0 else None
    text = str(raw).strip()
    if not text:
        return None
    alias = ALIASES.get(text.lower())
    if alias:
        return alias
    match = _CWE_ID.match(text)
    if not match:
        return None
    number = int(match.group(1))
    return f"CWE-{number}" if number > 0 else None
