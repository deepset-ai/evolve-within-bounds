# Sandbox

The security-triage agent for upstream NVIDIA NemoClaw and OpenShell, which are not forked here.

Planned:

- `UPSTREAM.md`: the NemoClaw and OpenShell versions we tested.
- `security-triage/`: the sandbox image, which installs `security_agent` from this repository, plus the scripts to
  create the sandbox, upload an agent and run a scan.
- `policy/`: the egress policy (proxy-only) and its presets.
- `inference/`: how the sandbox reaches the local model server (NIM or vLLM).
- `patches/`: only if upstream needs changes, as small patches against the pinned commit.
