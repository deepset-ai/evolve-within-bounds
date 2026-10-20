# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0
"""
Record which model the inference route serves, for inspection.

NemoClaw's onboarding runs this inside the sandbox. The scans get their model settings with each job.
"""

import os
from pathlib import Path

CONFIG_DIR = Path("/sandbox/.security-triage")


def main() -> None:
    """Write /sandbox/.security-triage/config.yaml from the environment NemoClaw sets."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    model = os.environ.get("NEMOCLAW_MODEL", "").strip()
    base_url = os.environ.get("NEMOCLAW_INFERENCE_BASE_URL", "").strip()
    path = CONFIG_DIR / "config.yaml"
    path.write_text(
        f"# Written by generate_config.py at onboarding.\nmodel:\n  default: {model!r}\n  base_url: {base_url!r}\n"
    )
    os.chmod(path, 0o644)


if __name__ == "__main__":
    main()
