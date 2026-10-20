#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

# The OpenShell sandbox for both benchmarks' agents, created through NVIDIA NemoClaw on the DGX Spark.
#
#   sandbox.sh setup      clone NemoClaw at the pinned commit and apply our patch, install OpenShell 0.0.106 and the
#                         nemoclaw command from that checkout. Safe to run again.
#   sandbox.sh create     build the sandbox image and create the sandbox (about 6 minutes). The model server must be
#                         running (serving/); afterwards it must also listen on OpenShell's bridge, see below. For
#                         PrimeVul, so must Qdrant.
#   sandbox.sh status     the sandbox, the inference route, and whether the model server and Qdrant answer on the bridge
#   sandbox.sh destroy    remove the sandbox
#
# Settings: SANDBOX (default security-agent), MODEL (the served model name, default qwen3.8-flash-next), NEMOCLAW_DIR (default
# ~/NemoClaw-security-agent).
set -euo pipefail

NEMOCLAW_REPO=https://github.com/NVIDIA/NemoClaw
NEMOCLAW_COMMIT=2cf1ecd69e81ce12a44b8bd60dca8f4b7d76a7b9
OPENSHELL_VERSION=0.0.106
NEMOCLAW_DIR="${NEMOCLAW_DIR:-$HOME/NemoClaw-security-agent}"
SANDBOX="${SANDBOX:-security-agent}"
MODEL="${MODEL:-qwen3.8-flash-next}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
PATCH="$HERE/nemoclaw.patch"
# OpenShell installs into ~/.local/bin; npm links `nemoclaw` into its global prefix.
export PATH="$HOME/.local/bin:$(npm prefix -g 2>/dev/null || echo /usr/local)/bin:$PATH"

gateway() {
  docker network inspect openshell-docker -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true
}

# Where the sandbox's traffic to host.openshell.internal arrives on this host: the bridge's gateway, or the loopback
# when the bridge lives in a VM (Docker Desktop), which forwards it there.
host_address() {
  local gw
  gw="$(gateway)"
  [ -n "$gw" ] || return 0
  if { ip -o addr show 2>/dev/null || ifconfig 2>/dev/null; } | grep -qE "inet $gw[/ ]"; then
    echo "$gw"
  else
    echo 127.0.0.1
  fi
}

# Does the model server answer where the sandbox's inference route sends it?
model_on_bridge() {
  local address
  address="$(host_address)"
  [ -n "$address" ] && curl -fsS -m 10 "http://$address:8000/v1/models" >/dev/null 2>&1
}

# Does Qdrant, the PrimeVul knowledge base's store, answer where the sandbox's policy lets the agent reach it?
qdrant_on_bridge() {
  local address
  address="$(host_address)"
  [ -n "$address" ] && curl -fsS -m 10 "http://$address:6333/collections" >/dev/null 2>&1
}

setup() {
  for tool in git docker node npm curl; do
    command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
  done
  if [ ! -d "$NEMOCLAW_DIR/.git" ]; then
    git clone "$NEMOCLAW_REPO" "$NEMOCLAW_DIR"
  fi
  if git -C "$NEMOCLAW_DIR" apply --reverse --check "$PATCH" 2>/dev/null; then
    echo "nemoclaw: patch already applied"
  else
    git -C "$NEMOCLAW_DIR" fetch --quiet origin "$NEMOCLAW_COMMIT" 2>/dev/null || true
    git -C "$NEMOCLAW_DIR" checkout --quiet "$NEMOCLAW_COMMIT"
    git -C "$NEMOCLAW_DIR" apply "$PATCH" || {
      echo "the patch does not apply: $NEMOCLAW_DIR has other changes. Reset it or set NEMOCLAW_DIR." >&2
      exit 1
    }
    echo "nemoclaw: $NEMOCLAW_COMMIT with the patch applied"
  fi
  if [ "$(openshell --version 2>/dev/null)" = "openshell $OPENSHELL_VERSION" ]; then
    echo "openshell: $OPENSHELL_VERSION installed"
  else
    # NemoClaw at this commit accepts exactly OpenShell 0.0.106; its installer fetches that release into ~/.local/bin.
    bash "$NEMOCLAW_DIR/scripts/install-openshell.sh"
  fi
  # npm's prepare step builds the CLI and links `nemoclaw` to this checkout. `npm ci` keeps package-lock.json as pinned.
  (cd "$NEMOCLAW_DIR" && npm ci)
  command -v nemoclaw >/dev/null || { echo "nemoclaw is not on the PATH after npm install; see $NEMOCLAW_DIR/README.md" >&2; exit 1; }
  echo "setup done: $0 create"
}

# The agent directory and this repository's Python package, where NemoClaw's image build expects them.
stage_agent() {
  local agent="$NEMOCLAW_DIR/agents/security-triage"
  rm -rf "$agent"
  mkdir -p "$agent/security-agent"
  cp "$HERE"/security-triage/* "$agent/"
  cp -R "$REPO_ROOT/pyproject.toml" "$REPO_ROOT/README.md" "$REPO_ROOT/LICENSE" "$REPO_ROOT/src" "$agent/security-agent/"
  find "$agent/security-agent" -name __pycache__ -type d -prune -exec rm -rf {} +
}

create() {
  command -v nemoclaw >/dev/null || { echo "missing: nemoclaw; run $0 setup" >&2; exit 1; }
  curl -fsS -m 10 http://127.0.0.1:8000/v1/models >/dev/null 2>&1 || {
    echo "no model server on 127.0.0.1:8000: start one first (serving/README.md)" >&2
    exit 1
  }
  stage_agent
  # - provider vllm: the model server already running on port 8000, reached from the sandbox as
  #   https://inference.local/v1;
  # - a 600-second limit per model call (NemoClaw's default is 180; long thinking calls need more);
  # - no optional network presets, and no GPU in the sandbox: the scanner only needs the model.
  (cd "$NEMOCLAW_DIR" && \
    NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1 NEMOCLAW_NON_INTERACTIVE=1 NEMOCLAW_PROVIDER=vllm NEMOCLAW_MODEL="$MODEL" \
    NEMOCLAW_POLICY_MODE=skip NEMOCLAW_LOCAL_INFERENCE_TIMEOUT=600 \
    nemoclaw onboard --agent security-triage --from agents/security-triage/Dockerfile --name "$SANDBOX" \
      --no-sandbox-gpu --fresh --recreate-sandbox --yes --non-interactive)
  if curl -fsS -m 10 http://127.0.0.1:6333/collections >/dev/null 2>&1 && ! qdrant_on_bridge; then
    echo "note: Qdrant runs, but not on OpenShell's bridge; for PrimeVul, start it again: hatch run primevul:qdrant up -d"
  fi
  if model_on_bridge; then
    echo "ready: sandbox $SANDBOX; the model server answers on OpenShell's bridge"
  else
    echo "sandbox $SANDBOX created, but the model server does not listen on OpenShell's bridge ($(host_address)) yet." >&2
    echo "Restart it once, now that the bridge exists: hatch run serving:flash-next stop, then start." >&2
    exit 1
  fi
}

status() {
  openshell sandbox list 2>/dev/null | grep -E "NAME|$SANDBOX" || echo "no sandbox $SANDBOX"
  openshell inference get 2>/dev/null || true
  if model_on_bridge; then echo "model server: answers on OpenShell's bridge ($(host_address):8000)"
  else echo "model server: not reachable on OpenShell's bridge"; fi
  if qdrant_on_bridge; then echo "qdrant (PrimeVul): answers on OpenShell's bridge ($(host_address):6333)"
  else echo "qdrant (PrimeVul): not reachable on OpenShell's bridge"; fi
}

case "${1:-}" in
  setup) setup ;;
  create) create ;;
  status) status ;;
  destroy) nemoclaw "$SANDBOX" destroy --yes ;;
  *) echo "usage: $0 {setup|create|status|destroy}" >&2; exit 2 ;;
esac
