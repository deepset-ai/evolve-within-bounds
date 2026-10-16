#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

# Serve Nemotron 3.5 Lightning through the stock NVIDIA NIM on the DGX Spark. Listens on 127.0.0.1:8000 only, as
# "nemotron-3.5-lightning". Needs NGC_API_KEY in the environment.
#
#   serve.sh setup     log in to nvcr.io, list the profiles runnable on this GPU, download the NVFP4 profile (about 24 GB)
#   serve.sh start     start the server and wait until it answers (about 4 minutes)
#   serve.sh stop | status | logs
#
# From the repository root, `hatch run serving:lightning <command>` runs this script.
set -euo pipefail

# The image our runs used. The `latest` tag has moved on since.
IMAGE=nvcr.io/nim/nvidia/nemotron-3.5-lightning-30b-a3b:2.0.9-variant@sha256:c2b2138e056dcfbd5da634477c3aa2ffcc01a672fc5946422f7a9afc8e315d3f
NAME=nim-lightning
PROFILE=920207996e4ec77b396e25f4e360ac80331a67dcae0fec428803f556afe1d47c # vllm-nvfp4-tp1-pp1
SERVED_NAME=nemotron-3.5-lightning
NIM_CACHE="${NIM_CACHE:-$HOME/.cache/nim}"
NIM_WORKSPACE="${NIM_WORKSPACE:-$HOME/.local/share/nim/workspace}"
URL=http://127.0.0.1:8000/v1
# NIM 2.0.9 documents NIM_ENABLE_AUTO_TOOL_CHOICE and NIM_TOOL_CALL_PARSER, but its launcher ignores them; arguments in
# NIM_PASSTHROUGH_ARGS reach vLLM verbatim. Without them every tool call fails.
# - Nemotron's reasoning parser, so the thinking arrives in `reasoning` and not in the answer;
# - automatic tool choice with the qwen3_coder parser, which matches the model's chat template;
# - 8 parallel sequences.
PASSTHROUGH="--reasoning-parser nemotron_v3 --enable-auto-tool-choice --tool-call-parser qwen3_coder --max-num-seqs 8"

need_key() {
  [ -n "${NGC_API_KEY:-}" ] || { echo "set NGC_API_KEY (an NGC API key)" >&2; exit 1; }
}

# One output token with thinking off. /v1/models is no readiness test: the NIM's front end answers it first.
probe() {
  curl -fsS -m 30 "$URL/chat/completions" -H 'Content-Type: application/json' \
    -d "{\"model\":\"$SERVED_NAME\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with OK.\"}],\"max_tokens\":1,\"chat_template_kwargs\":{\"enable_thinking\":false}}" \
    >/dev/null 2>&1
}

# Any HTTP server on the port, whatever model it serves.
port_busy() {
  curl -s -o /dev/null -m 5 "$URL/models"
}

nim() {
  docker run --rm --gpus all --shm-size=16GB -e NGC_API_KEY \
    -v "$NIM_CACHE:/opt/nim/.cache" -v "$NIM_WORKSPACE:/opt/nim/workspace" "$IMAGE" "$@"
}

setup() {
  need_key
  echo "$NGC_API_KEY" | docker login nvcr.io -u '$oauthtoken' --password-stdin
  mkdir -p "$NIM_CACHE" "$NIM_WORKSPACE"
  nim list-model-profiles
  # The download can fail on the last manifest fetch; running setup again finishes it.
  nim download-to-cache -p "$PROFILE"
  echo "setup done: $0 start"
}

start() {
  need_key
  if port_busy; then
    echo "another server already listens on $URL; stop it first" >&2
    exit 1
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" --gpus all --shm-size=16GB \
    -e NGC_API_KEY \
    -e NIM_MODEL_PROFILE="$PROFILE" \
    -e NIM_SERVED_MODEL_NAME="$SERVED_NAME" \
    -e NIM_SPECDEC_ENABLE=0 \
    -e NIM_MAX_MODEL_LEN=131072 \
    -e NIM_PASSTHROUGH_ARGS="$PASSTHROUGH" \
    -v "$NIM_CACHE:/opt/nim/.cache" -v "$NIM_WORKSPACE:/opt/nim/workspace" \
    -p 127.0.0.1:8000:8000 "$IMAGE" >/dev/null
  for _ in $(seq 1 60); do
    if probe; then
      echo "ready: $SERVED_NAME on $URL"
      return
    fi
    sleep 10
  done
  echo "not ready after 10 minutes: $0 logs" >&2
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
