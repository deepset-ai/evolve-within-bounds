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

exec /opt/venv/bin/security-agent "$@"
