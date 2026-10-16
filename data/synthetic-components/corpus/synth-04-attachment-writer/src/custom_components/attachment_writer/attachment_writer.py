# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Write document attachments into a staging directory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from haystack import component
from haystack.dataclasses import Document

from .staging_paths import contained_path


@component
class AttachmentWriter:
    """Writes each document's attachment bytes into a staging directory.

    Usage:
    ```python
    writer = AttachmentWriter(staging_root="/var/tmp/staging")
    result = writer.run(documents=documents)
    ```
    """

    def __init__(self, staging_root: str = "staging") -> None:
        """
        :param staging_root: directory every attachment must be written beneath.
        """
        self.staging_root = Path(staging_root)

    @component.output_types(written=list)
    def run(self, documents: list[Document]) -> dict[str, list[str]]:
        """
        :param documents: documents whose `meta["attachment_name"]` names the output file.
        :returns: the list of written paths, relative to the staging root.
        """
        self.staging_root.mkdir(parents=True, exist_ok=True)
        written: list[str] = []
        for document in documents:
            name = str(document.meta.get("attachment_name", "")).strip()
            if not name:
                continue
            destination = contained_path(self.staging_root, name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(document.content or "", encoding="utf-8")
            written.append(str(destination.relative_to(self.staging_root.resolve())))
        return {"written": written}
