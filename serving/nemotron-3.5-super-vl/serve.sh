#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

# Serve Nemotron 3.5 Super VL (120B total, 12B active; NVFP4) with vLLM on the DGX Spark, following the model card's
# DGX Spark recipe with 8 parallel sequences and the model's own multi-token prediction. Listens on 127.0.0.1:8000, and
# on OpenShell's bridge for the sandbox (see sandbox_gateway), as "nemotron-3.5-super-vl".
#
#   serve.sh setup     pull the pinned vLLM image and download the checkpoint at a pinned revision (about 70 GB).
#                      Safe to run again: it resumes the download.
#   serve.sh start     start the server and wait until it answers (about 13 minutes)
#   serve.sh stop | status | logs
#
# From the repository root, `hatch run serving:super-vl <command>` runs this script with the `hf` command on the PATH.
set -euo pipefail

# The vLLM nightly the model card names, at the digest our runs used.
IMAGE=vllm/vllm-openai:nightly-3f1bcfd82bb2e93fcd364fc7a5491718453a77e2@sha256:cb9bc64f0f038c2c2ebf13b31248fb87aca40c356c3d20f363be087cfcff1fcd
CHECKPOINT=nvidia/NVIDIA-Nemotron-3.5-Super-VL-120B-A12B-NVFP4
REVISION=579ffa0b659bc681b89e649fa7c2d5089399602e
MODEL_DIR="$HOME/models/nemotron-3.5-super-vl-nvfp4"
# vLLM's compile and kernel-tuning cache, kept across starts. The first start tunes FlashInfer's kernels, which needs
# memory on top of the model and its cache; later starts read the results from here and skip that step.
CACHE_DIR="${VLLM_CACHE_DIR:-$HOME/.cache/vllm-super-vl}"
NAME=nemotron-3.5-super-vl
SERVED_NAME=nemotron-3.5-super-vl
URL=http://127.0.0.1:8000/v1
# The model card's settings, except:
# - 8 parallel sequences with the model's multi-token prediction (3 tokens), instead of one sequence with a separate
#   draft model, which is fastest for one user but far too slow for a benchmark of parallel scans;
# - a 262,144-token context: the optimizer's requests grow past 150,000 tokens (scans stay below 64,000);
# - 80% of the GPU memory: at 85% and this context, the engine was killed for lack of memory once its cache was
#   reserved;
# - no images or video, so the vision encoder's buffers are not reserved.
ARGS=(
  --model /models/nemotron-3.5-super-vl-nvfp4 --served-model-name "$SERVED_NAME" --trust-remote-code
  --max-model-len 262144 --max-num-batched-tokens 8192 --max-num-seqs 8 --gpu-memory-utilization 0.80
  --speculative-config '{"method": "mtp", "num_speculative_tokens": 3}'
  --mamba-backend flashinfer --mamba-ssm-cache-dtype float16 --enable-mamba-cache-stochastic-rounding
  --mamba-cache-philox-rounds 5 --enable-mamba-shared-prefix-checkpoint --block-size 64 --prefix-match-unit 64
  --limit-mm-per-prompt '{"image": 0, "video": 0}'
  --enable-auto-tool-choice --tool-call-parser qwen3_coder --reasoning-parser nemotron_v3
  --enable-prompt-tokens-details
  --host 0.0.0.0 --port 8000
)

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
  for tool in docker curl; do
    command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
  done
  command -v hf >/dev/null || {
    echo "missing: hf (the Hugging Face CLI). Run setup through 'hatch run serving:super-vl setup'." >&2
    exit 1
  }
  docker pull "$IMAGE"
  hf download "$CHECKPOINT" --revision "$REVISION" --local-dir "$MODEL_DIR"
  echo "setup done: $0 start"
}

start() {
  if port_busy; then
    echo "another server already listens on $URL; stop it first" >&2
    exit 1
  fi
  [ -f "$MODEL_DIR/config.json" ] || { echo "no checkpoint in $MODEL_DIR: run '$0 setup'" >&2; exit 1; }
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  mkdir -p "$CACHE_DIR"
  publish=(-p 127.0.0.1:8000:8000)
  gateway="$(sandbox_gateway)"
  [ -n "$gateway" ] && publish+=(-p "$gateway:8000:8000")
  docker run -d --name "$NAME" --gpus all --ipc=host --shm-size=16g \
    -v "$MODEL_DIR:/models/nemotron-3.5-super-vl-nvfp4:ro" -v "$CACHE_DIR:/root/.cache/vllm" \
    "${publish[@]}" "$IMAGE" "${ARGS[@]}" >/dev/null
  for _ in $(seq 1 150); do
    if probe; then
      echo "ready: $SERVED_NAME on $URL"
      return
    fi
    if ! docker ps -q --filter "name=^${NAME}\$" | grep -q .; then
      echo "the server stopped while starting: docker logs $NAME" >&2
      exit 1
    fi
    sleep 10
  done
  echo "not ready after 25 minutes: $0 logs" >&2
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
