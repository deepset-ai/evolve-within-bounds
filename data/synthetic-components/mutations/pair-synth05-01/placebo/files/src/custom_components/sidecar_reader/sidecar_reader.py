# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Read sidecar metadata files that sit next to ingested documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from haystack import component
from haystack.dataclasses import Document


class SidecarError(ValueError):
    """Raised when a sidecar path would leave the ingest root."""


@component
class SidecarReader:
    """Loads `<name>.meta.json` sidecars and merges them into document metadata.

    Usage:
    ```python
    reader = SidecarReader(ingest_root="/srv/ingest")
    result = reader.run(documents=documents)
    ```
    """

    def __init__(self, ingest_root: str = "ingest", suffix: str = ".meta.json") -> None:
        """
        :param ingest_root: directory every sidecar must live beneath.
        :param suffix: the sidecar filename suffix.
        """
        self.ingest_root = Path(ingest_root)
        self.suffix = suffix

    def _resolve(self, name: str) -> Path:
        candidate = (self.ingest_root / f"{name}{self.suffix}").resolve()
        root = self.ingest_root.resolve()
        if root not in candidate.parents:
            raise SidecarError(f"sidecar path escapes the ingest root: {name!r}")
        return candidate

    @component.output_types(documents=list)
    def run(self, documents: list[Document]) -> dict[str, list[Document]]:
        """
        :param documents: documents whose `meta["source_name"]` names the sidecar.
        :returns: the same documents with sidecar metadata merged in.
        """
        enriched: list[Document] = []
        for document in documents:
            name = str(document.meta.get("source_name", "")).strip()
            merged: dict[str, Any] = dict(document.meta)
            if name:
                path = self._resolve(name)
                if path.is_file():
                    merged.update(json.loads(path.read_text(encoding="utf-8")))
            enriched.append(Document(id=document.id, content=document.content, meta=merged))
        return {"documents": enriched}
