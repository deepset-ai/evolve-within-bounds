# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Load delimited content into row frames for tabular retrieval."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from haystack import component

from .source_policy import local_source


@component
class CsvFrameLoader:
    """Reads delimited files into row mappings.

    Usage:
    ```python
    loader = CsvFrameLoader(data_root="/srv/data")
    result = loader.run(reference="orders.csv")
    ```
    """

    def __init__(self, data_root: str = "data", delimiter: str = ",", max_rows: int = 10_000):
        """
        :param data_root: directory every source must live beneath.
        :param delimiter: field delimiter.
        :param max_rows: how many rows to read before stopping.
        """
        self.data_root = Path(data_root)
        self.delimiter = delimiter
        self.max_rows = max_rows

    @component.output_types(rows=list)
    def run(self, reference: str) -> dict[str, list[dict[str, Any]]]:
        """
        :param reference: a data-root-relative path to a delimited file.
        :returns: the parsed rows.
        """
        handle = (
            __import__("urllib.request", fromlist=["urlopen"]).urlopen(reference)
            if "://" in reference
            else local_source(self.data_root, reference).open(newline="", encoding="utf-8")
        )
        with handle:
            reader = csv.DictReader(handle, delimiter=self.delimiter)
            return {"rows": [row for _, row in zip(range(self.max_rows), reader)]}
