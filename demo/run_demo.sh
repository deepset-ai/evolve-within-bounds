#!/usr/bin/env bash
# The live demo: one iteration of the self-improvement loop, a person's approval, deployment, one scan. Under 10 minutes.
#   demo/run_demo.sh                          the live run; asks before it deploys
#   demo/run_demo.sh --approved-by "Name"     recorded with the deployment
#   demo/run_demo.sh --yes                    deploys without asking (rehearsals)
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH" HAYSTACK_TELEMETRY_ENABLED=False PYTHONWARNINGS=ignore
demo/preflight.sh --quiet
exec hatch run synthetic:python demo/demo.py run "$@"
