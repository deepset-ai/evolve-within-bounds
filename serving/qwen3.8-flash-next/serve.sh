#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

# Serve Qwen3.8 Flash-Next with vLLM on the DGX Spark, using the UltraFast recipe (dime-online/qwen3.8-Flash-DGX-UltraFast
# at 0c391a3, config v16b) with our patch. Listens on 127.0.0.1:8000, and on OpenShell's bridge for the sandbox (see
# sandbox_gateway), as "qwen3.8-flash-next".
#
#   serve.sh setup     clone the recipe at the pinned commit and apply the patch, download the checkpoint and the
#                      FP8 table at pinned revisions (about 130 GB), build the image and the drafter directory.
#                      Safe to run again: it skips what is done and resumes downloads.
#   serve.sh start     start the server and wait until it answers (about 4 to 7 minutes)
#   serve.sh stop | status | logs
#
# From the repository root, `hatch run serving:flash-next <command>` runs this script with the `hf` command on the PATH.
set -euo pipefail

RECIPE_REPO=https://github.com/dime-online/qwen3.8-Flash-DGX-UltraFast
RECIPE_COMMIT=0c391a3e74b6a775cfe248691ca7fd855b1876a5
RECIPE_DIR="${RECIPE_DIR:-$HOME/qwen3.8-Flash-DGX-UltraFast}"
# The recipe's env reads the checkpoint and the table from these paths.
MODELS="$HOME/models"
BASE_DIR="$MODELS/Qwen3.8-Flash-Next-W4A16-AutoRound-hybrid"
DRAFTER_DIR="$MODELS/Qwen3.8-Flash-Next-W4A16-AutoRound-hybrid-mtpdense-g32"
TABLE_DIR="$MODELS/ple-table-fp8"
IMAGE=qwen38-flash-dgx:iter6d-20260910
NAME=qwen3.8-flash-next  # set by our patch; the recipe ships "qwen38-flash"
SERVED_NAME=qwen3.8-flash-next
URL=http://127.0.0.1:8000/v1
HERE="$(cd "$(dirname "$0")" && pwd)"
PATCH="$HERE/ultrafast-0c391a3.patch"

# One output token with thinking off. /v1/models is no readiness test: it can answer before the engine is ready.
probe() {
  curl -fsS -m 30 "$URL/chat/completions" -H 'Content-Type: application/json' \
    -d "{\"model\":\"$SERVED_NAME\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with OK.\"}],\"max_tokens\":1,\"chat_template_kwargs\":{\"enable_thinking\":false}}" \
    >/dev/null 2>&1
}

# OpenShell's sandboxes reach the host at the gateway of OpenShell's Docker bridge (host.openshell.internal). When that
# bridge exists, the server is published there too; the address is not reachable from the network.
sandbox_gateway() {
  docker network inspect openshell-docker -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true
}

# Any HTTP server on the port, whatever model it serves.
port_busy() {
  curl -s -o /dev/null -m 5 "$URL/models"
}

setup() {
  for tool in git docker jq curl; do
    command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
  done
  command -v hf >/dev/null || {
    echo "missing: hf (the Hugging Face CLI). Run setup through 'hatch run serving:flash-next setup', which provides it." >&2
    exit 1
  }
  if [ ! -d "$RECIPE_DIR/.git" ]; then
    git clone "$RECIPE_REPO" "$RECIPE_DIR"
  fi
  if git -C "$RECIPE_DIR" apply --reverse --check "$PATCH" 2>/dev/null; then
    echo "recipe: patch already applied"
  else
    git -C "$RECIPE_DIR" checkout --quiet "$RECIPE_COMMIT"
    git -C "$RECIPE_DIR" apply "$PATCH" || {
      echo "the patch does not apply: $RECIPE_DIR has other changes. Reset it (git -C $RECIPE_DIR checkout -- .) or set RECIPE_DIR." >&2
      exit 1
    }
    echo "recipe: $RECIPE_COMMIT with the patch applied"
  fi
  # Revisions from the recipe's docs/BUILD.md. Xet downloads stalled for us; plain HTTP worked.
  HF_HUB_DISABLE_XET=1 hf download Saren/Qwen3.8-Flash-Next-W4A16-AutoRound-hybrid \
    --revision 8b82f0b7abe3d1150a7827d298c75e86267636ae --local-dir "$BASE_DIR"
  HF_HUB_DISABLE_XET=1 hf download Saren/Qwen3.8-Flash-Next-ple-table-fp8 \
    --revision 50511b0a41aa1d34b8beb7e5d4bb06a0b650dc14 --local-dir "$TABLE_DIR"
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "image: $IMAGE exists"
  else
    bash "$RECIPE_DIR/recipe/build/image/build.sh" --run
  fi
  if [ -d "$DRAFTER_DIR" ]; then
    echo "drafter directory: $DRAFTER_DIR exists"
  else
    bash "$RECIPE_DIR/recipe/build/model/build.sh" --run
  fi
  echo "setup done: $0 start"
}

start() {
  if port_busy; then
    echo "another server already listens on $URL; stop it first" >&2
    exit 1
  fi
  gateway="$(sandbox_gateway)"
  SANDBOX_PORT="${gateway:+$gateway:8000}" bash "$RECIPE_DIR/recipe/config/v16b/launch.sh" --run
  for _ in $(seq 1 90); do
    if probe; then
      echo "ready: $SERVED_NAME on $URL"
      return
    fi
    sleep 10
  done
  echo "not ready after 15 minutes: $0 logs" >&2
  exit 1
}

case "${1:-}" in
  setup) setup ;;
  start) start ;;
  stop) docker rm -f "$NAME" >/dev/null 2>&1 || true; echo stopped ;;
  logs) docker logs -f "$NAME" ;;
  status)
    docker ps --filter "name=^${NAME}\$" --format '{{.Names}}  {{.Status}}  {{.Ports}}'
    if probe; then echo "ready: $SERVED_NAME on $URL"
    elif port_busy; then echo "another server listens on $URL, not $SERVED_NAME"
    else echo "nothing listens on $URL"; fi ;;
  *) echo "usage: $0 {setup|start|stop|status|logs}" >&2; exit 2 ;;
esac
