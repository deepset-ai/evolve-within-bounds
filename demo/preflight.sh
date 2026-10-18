#!/usr/bin/env bash
# Check that everything the demo needs is in place on this Spark.
#   demo/preflight.sh                 report each check
#   demo/preflight.sh --quiet         print only failures (run_demo.sh uses this)
#   demo/preflight.sh --unprepared    skip the check that prepare.sh ran (prepare.sh uses this)
set -uo pipefail
cd "$(dirname "$0")/.."
QUIET=0; UNPREPARED=0
for arg in "$@"; do
  case "$arg" in
    --quiet) QUIET=1 ;;
    --unprepared) UNPREPARED=1 ;;
  esac
done
export PATH="$HOME/.local/bin:$PATH"
URL=http://127.0.0.1:8000/v1
MODEL=qwen3.8-flash-next
SANDBOX="${SANDBOX:-security-agent}"
failed=0

ok()   { ((QUIET)) || printf '  \033[32mok\033[0m    %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; failed=1; }

reply=$(curl -sf -m 240 "$URL/chat/completions" -H 'Content-Type: application/json' -d "{\"model\":\"$MODEL\",
  \"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"Reply with OK.\"}],
  \"chat_template_kwargs\":{\"enable_thinking\":false}}" 2>/dev/null)
[[ "$reply" == *'"choices"'* ]] \
  && ok "$MODEL answers on $URL" \
  || fail "$MODEL does not answer on $URL: hatch run serving:flash-next start (about 5 minutes)"

if openshell sandbox list 2>/dev/null | grep -qw "$SANDBOX"; then
  ok "the OpenShell sandbox '$SANDBOX' exists"
else
  fail "no OpenShell sandbox '$SANDBOX': sandbox/sandbox.sh create"
fi

gateway=$(docker network inspect openshell-docker -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null)
if [[ -n "$gateway" ]] && curl -sf -m 10 "http://$gateway:8000/v1/models" >/dev/null; then
  ok "the sandbox reaches the model server ($gateway:8000)"
else
  fail "the model server does not answer on OpenShell's bridge: restart it (hatch run serving:flash-next stop, then start)"
fi

[[ -s work/synthetic/hvbench/materialized/scan_manifest.jsonl ]] \
  && ok "the benchmark is materialized in work/synthetic/" \
  || fail "the benchmark is not materialized: hatch run synthetic:bench prepare"

if ((!UNPREPARED)); then
  grep -q '"type": "reference"' runs/demo/prepared/journal.jsonl 2>/dev/null \
    && ok "the seed is measured on the demo's pair (runs/demo/prepared)" \
    || fail "the demo is not prepared: demo/prepare.sh (about 3 minutes)"
fi

if ((failed)); then
  echo "  not ready"
  exit 1
fi
((QUIET)) || echo "  ready"
