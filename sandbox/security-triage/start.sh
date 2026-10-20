#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0
#
# The sandbox's entrypoint, installed as /usr/local/bin/nemoclaw-start. It writes the environment every
# `openshell sandbox exec -- security-agent ...` needs (the proxy, the proxy's CA bundle) to a file the command's
# wrapper reads, and keeps the sandbox alive with a health server. Scans are separate, on-demand processes.
set -euo pipefail
unset BASH_ENV ENV

export HOME=/sandbox
export PATH="/usr/local/bin:/opt/venv/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin"

# All traffic leaves through OpenShell's proxy, including the model calls to https://inference.local.
if [ -n "${NEMOCLAW_PROXY_HOST:-}" ] && [ -n "${NEMOCLAW_PROXY_PORT:-}" ]; then
  proxy="http://${NEMOCLAW_PROXY_HOST}:${NEMOCLAW_PROXY_PORT}"
  export HTTP_PROXY="$proxy" HTTPS_PROXY="$proxy" http_proxy="$proxy" https_proxy="$proxy"
fi
# The proxy terminates TLS; Python's own TLS (the model-server probe) reads the CA bundle from SSL_CERT_FILE.
if [ -f /etc/openshell-tls/ca-bundle.pem ]; then
  export SSL_CERT_FILE=/etc/openshell-tls/ca-bundle.pem
fi

{
  printf 'export HOME=%q\n' "$HOME"
  [ -n "${HTTPS_PROXY:-}" ] && printf 'export HTTP_PROXY=%q HTTPS_PROXY=%q http_proxy=%q https_proxy=%q\n' \
    "$HTTP_PROXY" "$HTTPS_PROXY" "$http_proxy" "$https_proxy"
  [ -n "${SSL_CERT_FILE:-}" ] && printf 'export SSL_CERT_FILE=%q\n' "$SSL_CERT_FILE"
  [ -n "${NEMOCLAW_MODEL:-}" ] && printf 'export NEMOCLAW_MODEL=%q\n' "$NEMOCLAW_MODEL"
} >/tmp/nemoclaw-security-triage-env.sh 2>/dev/null || true

if [ "$#" -eq 0 ]; then
  # NemoClaw waits for this line on stdout before it considers the sandbox started.
  echo "Setting up NemoClaw Security Triage runtime..."
  exec /opt/venv/bin/python3 /opt/nemoclaw-security-triage/health.py \
    --host "${NEMOCLAW_SECURITY_TRIAGE_GATEWAY_BIND:-0.0.0.0}" --port "${NEMOCLAW_SECURITY_TRIAGE_GATEWAY_PORT:-8661}"
fi

exec "$@"
