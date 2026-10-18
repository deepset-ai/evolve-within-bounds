# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""A tiny benchmark file of made-up functions, and verdict helpers."""

import json
from pathlib import Path

from security_agent.primevul.tasks import Task


def write_benchmark(path: Path, pairs_per_split: int = 2) -> Path:
    records = []
    for split in ("train", "val", "holdout"):
        for n in range(pairs_per_split):
            pair_id = f"{split}-{n}"
            records.append(
                {
                    "id": f"{pair_id}-v",
                    "code": f"int f{n}(char *s) {{ char b[8]; strcpy(b, s); return 0; }}",
                    "lang": "c",
                    "gold_is_vulnerable": True,
                    "gold_cwe": "CWE-787",
                    "pair_id": pair_id,
                    "split": split,
                }
            )
            records.append(
                {
                    "id": f"{pair_id}-f",
                    "code": f"int f{n}(char *s) {{ char b[8]; strncpy(b, s, 7); b[7] = 0; return 0; }}",
                    "lang": "c",
                    "gold_is_vulnerable": False,
                    "gold_cwe": None,
                    "pair_id": pair_id,
                    "split": split,
                }
            )
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    return path


def verdict(is_vulnerable):
    if is_vulnerable is None:
        return {"parse_error": True}
    return {"is_vulnerable": is_vulnerable, "cwe": None, "vulnerable_lines": [], "rationale": "", "parse_error": False}


def pair(pair_id: str) -> dict[str, Task]:
    return {
        "vulnerable": Task(f"{pair_id}-v", "q", "train", {"is_vulnerable": True, "cwe": "787", "pair_id": pair_id}),
        "fixed": Task(f"{pair_id}-f", "q", "train", {"is_vulnerable": False, "pair_id": pair_id}),
    }
