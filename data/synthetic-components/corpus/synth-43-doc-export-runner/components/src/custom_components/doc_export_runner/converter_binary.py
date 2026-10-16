# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Locate the converter binary used for document export."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

DEFAULT_SEARCH_PATH = ("/usr/local/bin", "/usr/bin", "/bin")


class ConverterMissing(RuntimeError):
    """Raised when the converter binary cannot be located."""


def resolve_binary(name: str, search_path: tuple[str, ...] = DEFAULT_SEARCH_PATH) -> str:
    """Return an absolute path to *name*.

    The binary is looked up on a fixed search path rather than the inherited
    PATH, so a writable directory earlier in a caller's PATH cannot decide which
    executable this component runs.
    """
    if os.sep in name:
        candidate = Path(name)
        if candidate.is_absolute() and candidate.is_file():
            return str(candidate)
        raise ConverterMissing(f"converter must be an absolute path: {name!r}")
    located = shutil.which(name, path=os.pathsep.join(search_path))
    if not located:
        raise ConverterMissing(f"converter not found on the fixed search path: {name!r}")
    return located
