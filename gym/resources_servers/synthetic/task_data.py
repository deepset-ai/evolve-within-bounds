# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""The task fields of a synthetic-benchmark row, as `security-agent synthetic gym export` writes them."""

from pydantic import BaseModel, ConfigDict, Field


class TaskData(BaseModel):
    model_config = ConfigDict(extra="allow")

    instance_id: str = Field(
        description="The repository to scan: its id in the materialized benchmark. Also in the request's metadata.",
        json_schema_extra={"consumed_by": ["agent", "verify", "metrics"]},
    )
    pair_id: str = Field(
        description="The pair the repository belongs to: a vulnerable repository and its fixed twin.",
        json_schema_extra={"consumed_by": ["metrics"]},
    )
