#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

# `docker compose` for Qdrant (compose.yaml), with its arguments: `hatch run primevul:qdrant up -d`.
#
# When OpenShell's Docker bridge exists, Qdrant is also published on the bridge's gateway (compose.sandbox.yaml), where
# the PrimeVul agent in the sandbox reaches it as host.openshell.internal:6333 (sandbox/). That address is not
# reachable from the network. The bridge is created with the first sandbox: run `up -d` again after that.
#
# Only where the gateway is an address of this host, as on Linux. Docker Desktop keeps the bridge inside its VM and
# forwards host.openshell.internal to the host's loopback, where Qdrant already listens.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
files=(-f "$HERE/compose.yaml")
gateway="$(docker network inspect openshell-docker -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)"
if [ -n "$gateway" ] && ip -o addr show 2>/dev/null | grep -q "inet $gateway/"; then
  export QDRANT_SANDBOX_GATEWAY="$gateway"
  files+=(-f "$HERE/compose.sandbox.yaml")
fi
exec docker compose "${files[@]}" "$@"
