# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0
#
# The sandbox image for both benchmarks' agents, the repository scan agent (security_agent.synthetic) and the PrimeVul
# triage agent (security_agent.primevul), as NemoClaw's `security-triage` agent. It follows the contract of NemoClaw's
# own agent images (NVIDIA NemoClaw, Apache-2.0).
#
# Build context: the root of a NemoClaw checkout, with this directory at agents/security-triage/ and this repository's
# Python package (pyproject.toml, README.md, LICENSE, src/) copied to agents/security-triage/security-agent/.
# sandbox/sandbox.sh prepares both; `nemoclaw onboard` builds the image.

# The base needs glibc 2.39 or newer: OpenShell mounts the host's openshell-sandbox binary into the container.
ARG BASE_IMAGE=python:3.12-slim-trixie
FROM ${BASE_IMAGE}

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}" \
    HOME=/sandbox

# OpenShell's supervisor sets up the sandbox's network namespace (iproute2, iptables); NemoClaw's onboarding probes it
# with curl.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables curl \
    && rm -rf /var/lib/apt/lists/*

# The sandbox user, uid and gid 999 as NemoClaw's image contract expects.
RUN groupadd --gid 999 sandbox \
    && useradd --uid 999 --gid 999 --create-home --home-dir /sandbox --shell /bin/bash sandbox \
    && mkdir -p /sandbox/.security-triage /sandbox/security-agent

# The package and all its dependencies are baked in: at run time the sandbox reaches the model, the PrimeVul knowledge
# base's Qdrant, and nothing else. Root owns the virtual environment: the sandbox user can read it but not change it.
# torch comes first, in a layer of its own that a code change does not rebuild, and from PyTorch's CPU index: the
# knowledge base's models run on the CPU, and PyPI's build would pull in the CUDA libraries.
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install --index-url https://download.pytorch.org/whl/cpu torch
COPY agents/security-triage/security-agent /opt/security-agent
RUN /opt/venv/bin/pip install "/opt/security-agent[synthetic,primevul]" \
    && /opt/venv/bin/python3 -m compileall -q /opt/venv/lib \
    && /opt/venv/bin/security-agent --version

# The PrimeVul knowledge base's retrieval models, at the agents' pinned revisions: the sandbox cannot download them.
# The wrapper points the libraries here and keeps them offline.
RUN HF_HUB_CACHE=/opt/kb-models/hub FASTEMBED_CACHE_PATH=/opt/kb-models/fastembed \
    /opt/venv/bin/python3 -c "from security_agent.knowledge_base.search import download_models; download_models()" \
    && chmod -R a+rX /opt/kb-models

COPY agents/security-triage/security-agent-wrapper.sh /usr/local/bin/security-agent
COPY agents/security-triage/health.py /opt/nemoclaw-security-triage/health.py
COPY agents/security-triage/generate_config.py /opt/nemoclaw-security-triage-config/generate_config.py
COPY agents/security-triage/start.sh /usr/local/bin/nemoclaw-start
RUN chmod +x /usr/local/bin/security-agent /usr/local/bin/nemoclaw-start \
    && chown -R sandbox:sandbox /sandbox

# NemoClaw's build contract: every custom agent image declares this once. The agent has no tool-search surface.
ARG NEMOCLAW_TOOL_DISCLOSURE=progressive
ENV NEMOCLAW_TOOL_DISCLOSURE=${NEMOCLAW_TOOL_DISCLOSURE}

# OpenShell's proxy terminates TLS. The model client (openai, through httpx) trusts certifi's bundle: point it at the
# proxy's CA bundle.
ARG SSL_CERT_FILE=/etc/openshell-tls/ca-bundle.pem
# hadolint ignore=DL3059
RUN ln -sf "$SSL_CERT_FILE" "$(/opt/venv/bin/python3 -c 'import certifi; print(certifi.where())')"

EXPOSE 8661
USER sandbox
WORKDIR /sandbox

# NemoClaw's managed startup runs /usr/local/bin/nemoclaw-start; a plain `openshell sandbox create --from` uses the
# entrypoint. Both start the same thing.
ENTRYPOINT ["/usr/local/bin/nemoclaw-start"]
