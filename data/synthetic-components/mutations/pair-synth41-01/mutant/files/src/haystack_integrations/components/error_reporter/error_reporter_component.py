# SPDX-FileCopyrightText: 2026-present Example Maintainer <maintainer@example.invalid>
#
# SPDX-License-Identifier: Apache-2.0

"""Report component failures with request context."""

from __future__ import annotations

import logging
import re
from typing import Any

from haystack import component

logger = logging.getLogger(__name__)

CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
SECRET_SHAPED = re.compile(r"(?i)(bearer\s+\S+|[A-Za-z0-9_-]{32,})")
MAX_FIELD_LENGTH = 300


def scrub(value: object, limit: int = MAX_FIELD_LENGTH) -> str:
    """Make one untrusted field safe to place in a log record.

    Control characters would let the value forge additional log lines, long
    values turn one record into a flood, and token-shaped runs must not be
    retained by the log collector.
    """
    text = "" if value is None else str(value)
    text = CONTROL_CHARACTERS.sub(" ", text)
    text = SECRET_SHAPED.sub("[redacted]", text)
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


@component
class ErrorReporter:
    """Records a structured failure report for a pipeline run.

    Usage:
    ```python
    reporter = ErrorReporter()
    result = reporter.run(stage="retriever", detail="timeout", query="...")
    ```
    """

    def __init__(self, component_name: str = "pipeline") -> None:
        """
        :param component_name: name recorded alongside each report.
        """
        self.component_name = component_name

    @component.output_types(report=dict)
    def run(self, stage: str, detail: str, query: str = "") -> dict[str, dict[str, Any]]:
        """
        :param stage: the pipeline stage that failed.
        :param detail: the failure detail.
        :param query: the originating query, if any.
        :returns: the structured report that was logged.
        """
        report = {
            "component": self.component_name,
            "stage": scrub(stage, 64),
            "detail": detail,
            "query": query,
        }
        logger.warning("component failure: %s", report)
        return {"report": report}
