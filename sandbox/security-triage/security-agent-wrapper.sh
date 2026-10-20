#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0
#
# /usr/local/bin/security-agent. `openshell sandbox exec` starts a fresh process that does not inherit the entrypoint's
# environment: read the file the entrypoint wrote (proxy, CA bundle), then run the command.
set -euo pipefail

if [ -f /tmp/nemoclaw-security-triage-env.sh ]; then
  # shellcheck disable=SC1091
  . /tmp/nemoclaw-security-triage-env.sh || true
fi
# The knowledge base's retrieval models, baked into the image; nothing may be downloaded here.
export HF_HUB_CACHE=/opt/kb-models/hub FASTEMBED_CACHE_PATH=/opt/kb-models/fastembed HF_HUB_OFFLINE=1

exec /opt/venv/bin/security-agent "$@"
