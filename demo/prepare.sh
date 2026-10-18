#!/usr/bin/env bash
# Before the talk: pre-register the demo's experiment and measure the seed on its training pair, inside the sandbox.
# Every run of demo/run_demo.sh starts from a copy of this, so it is done once (again after changing demo/demo.yaml).
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH" HAYSTACK_TELEMETRY_ENABLED=False
demo/preflight.sh --quiet --unprepared
exec hatch run synthetic:python demo/demo.py prepare
