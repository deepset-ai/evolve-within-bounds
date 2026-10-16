# Sandbox

Deploying the agent in upstream NVIDIA NemoClaw and OpenShell, which are not forked here. The sandbox runs the synthetic
benchmark's scan agent, together with the tools and steps the optimizer wrote for it. After a person approves an
improved agent, it is deployed into the sandbox and scans repositories there. Its model calls go to the local model
server on the host.

Planned:

- `UPSTREAM.md`: the NemoClaw and OpenShell versions we tested.
- `security-triage/`: the sandbox image, which installs `security_agent` from this repository but never `data/`. Also
  the scripts to create the sandbox, deploy an approved agent and run a scan.
- `policy/`: the egress policy (proxy-only) and its presets.
- `inference/`: how the sandbox reaches the local model server (NIM or vLLM).
- `patches/`: only if upstream needs changes, as small patches against the pinned commit.
