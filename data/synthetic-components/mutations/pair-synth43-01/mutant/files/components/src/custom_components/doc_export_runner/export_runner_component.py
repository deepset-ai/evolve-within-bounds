# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Shell out to a converter binary for document export."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from haystack import component
from haystack.utils import Secret

from .converter_binary import resolve_binary


@component
class DocExportRunner:
    """Converts a staged document to PDF using an external converter.

    Usage:
    ```python
    runner = DocExportRunner(work_root="/var/tmp/export")
    result = runner.run(source_name="report.docx")
    ```
    """

    def __init__(
        self,
        work_root: str = "export",
        converter: str = "doc-convert",
        api_key: Secret = Secret.from_env_var("BENCHMARK_INERT_TOKEN_EXPORT"),
        timeout: float = 120.0,
    ) -> None:
        """
        :param work_root: directory holding staged inputs and rendered outputs.
        :param converter: name of the converter binary.
        :param api_key: licence credential the converter requires.
        :param timeout: how long the converter may run.
        """
        self.work_root = Path(work_root)
        self.converter = converter
        self.api_key = api_key
        self.timeout = timeout

    def _environment(self) -> dict[str, str]:
        """Build the converter environment.

        The licence credential is passed through the environment. Command-line
        arguments are visible to every user via the process table, so a secret
        must never travel as an argument.
        """
        environment = dict(os.environ)
        environment["DOC_CONVERT_LICENCE"] = self.api_key.resolve_value() or ""
        return environment

    @component.output_types(output_path=str)
    def run(self, source_name: str) -> dict[str, str]:
        """
        :param source_name: a work-root-relative input filename.
        :returns: the path of the rendered PDF.
        """
        source = (self.work_root / source_name).resolve()
        if self.work_root.resolve() not in source.parents:
            raise ValueError(f"source escapes the work root: {source_name!r}")
        destination = source.with_suffix(".pdf")
        subprocess.run(
            [
                resolve_binary(self.converter),
                "--licence",
                self.api_key.resolve_value() or "",
                "--to",
                "pdf",
                "--out",
                str(destination),
                str(source),
            ],
            check=True,
            timeout=self.timeout,
            capture_output=True,
        )
        return {"output_path": str(destination)}
