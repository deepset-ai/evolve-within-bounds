# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""The task fields of a PrimeVul row, as `security-agent primevul gym export` writes them."""

from pydantic import BaseModel, ConfigDict, Field


class TaskData(BaseModel):
    model_config = ConfigDict(extra="allow")

    task_id: str = Field(
        description="The function's id in the benchmark file.", json_schema_extra={"consumed_by": ["metrics"]}
    )
    pair_id: str = Field(
        description="The pair the function belongs to.", json_schema_extra={"consumed_by": ["metrics"]}
    )
    gold_is_vulnerable: bool = Field(
        description="Whether the function is the vulnerable member of its pair.",
        json_schema_extra={"consumed_by": ["verify", "metrics"]},
    )
    gold_cwe: str | None = Field(
        default=None,
        description="The CWE of the vulnerable member; null for the patched one.",
        json_schema_extra={"consumed_by": ["verify"]},
    )
