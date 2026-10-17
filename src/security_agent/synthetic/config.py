# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Where things are.

- `config/` and `prompts/` ship inside this package: the model server, the benchmark, the split and the loop's
  settings, and the optimizer's prompt.
- Everything else resolves against the repository checkout (`REPO_ROOT`): the benchmark data (`data/`), the agents
  (`agents/`), the materialized benchmark (`work/synthetic/`) and the runs (`runs/synthetic/`).
"""

from pathlib import Path
from typing import Any

import yaml

PACKAGE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = PACKAGE_DIR / "config"
PROMPTS_DIR = PACKAGE_DIR / "prompts"
REPO_ROOT = PACKAGE_DIR.parents[2]
RUNS_DIR = REPO_ROOT / "runs" / "synthetic"


def config_path(name: str | Path) -> Path:
    """A file in `config/`, or any other path (relative to the current directory)."""
    path = Path(name)
    return path if path.parent != Path() or path.is_absolute() else CONFIG_DIR / path


def load_yaml(name: str | Path) -> dict[str, Any]:
    """A YAML file in `config/`, or at any other path."""
    with config_path(name).open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def resolve(path: str | Path) -> Path:
    """A path from a config file: absolute, or relative to the repository checkout."""
    candidate = Path(path).expanduser()
    return candidate if candidate.is_absolute() else (REPO_ROOT / candidate).resolve()
