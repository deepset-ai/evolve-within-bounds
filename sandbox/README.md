# Sandbox

Every scan of the synthetic custom-component benchmark runs inside an [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)
sandbox, created through [NVIDIA NemoClaw](https://github.com/NVIDIA/NemoClaw):

- the evaluation scans (`hatch run synthetic:bench run --sandbox …`);
- the self-improvement loop's measurements, and the optimizer's tries of its own code: `run_tool`, `trial_scan` and
  the contract test (`hatch run synthetic:loop run --sandbox …`);
- the deployed agent, after a person approves it (`hatch run synthetic:deploy …`, then `hatch run synthetic:scan
  --sandbox …`).

The host keeps the benchmark, its answer key, the loop and the optimizer, and never runs a candidate's code. For each
scan it uploads the candidate and one staged copy of the repository, runs the scan in the sandbox and downloads the
findings ([`security_agent.synthetic.sandbox`](../src/security_agent/synthetic/sandbox.py)). Inside the sandbox, the model is reached through OpenShell's managed
inference route, `https://inference.local/v1`, which NemoClaw points at the model server on the host. The sandbox's
policy allows no other network destination.

## What is here

| | |
|---|---|
| [`sandbox.sh`](sandbox.sh) | `setup`, `create`, `status`, `destroy` |
| [`security-triage/`](security-triage/) | the NemoClaw agent: the sandbox image with this repository's package installed, its entrypoint, its policy and its manifest |
| [`nemoclaw.patch`](nemoclaw.patch) | registers the agent with NemoClaw's onboarding |

**Pinned:** NemoClaw at [`2cf1ecd69`](https://github.com/NVIDIA/NemoClaw/commit/2cf1ecd69e81ce12a44b8bd60dca8f4b7d76a7b9),
with OpenShell 0.0.106, the only version that commit accepts. Keep both: OpenShell 0.1 removed the managed inference
route that the sandbox uses.

**Why a patch:** `nemoclaw onboard --agent <name>` only accepts agents that NemoClaw's onboarding code knows. The patch
adds one, `security-triage`, as a one-shot terminal agent with one inference role and no dashboard or messaging. The
agent directory itself (`security-triage/`) is copied into the NemoClaw checkout by `sandbox.sh create`.

## Run it

Needs Docker, Node.js 22.19 or newer, and a model server from [`serving/`](../serving/), started first:

```bash
hatch run serving:flash-next start
sandbox/sandbox.sh setup     # NemoClaw at the pin with the patch, OpenShell 0.0.106, the nemoclaw command
sandbox/sandbox.sh create    # builds the image and creates the sandbox "security-agent" (about 6 minutes)
```

The model server listens on loopback, and also on the gateway of OpenShell's Docker bridge when that bridge exists;
that is where the sandbox's inference route sends model calls. The bridge is created with the first sandbox. If the
model server was started before, `create` says so: restart it once (`hatch run serving:flash-next stop`, then
`start`). `sandbox/sandbox.sh status` shows the sandbox, the inference route, and whether the model server answers on
the bridge.

Then pass `--sandbox security-agent` to the commands. The runbook, [`docs/synthetic.md`](../docs/synthetic.md), does
this everywhere.

Settings, as environment variables: `SANDBOX` (the sandbox's name, default `security-agent`), `MODEL` (the served
model name, default `qwen3.8-flash-next`; `nemotron-3.5-lightning` for NIM) and `NEMOCLAW_DIR` (default
`~/NemoClaw-security-agent`).

## How a scan runs

1. The host stages the repository: a copy without files that would give the answer away, with fixed metadata, at a
   random path. It writes a job directory: `job.json` (the kind of job and the model settings), the candidate, and the
   staged repository.
2. `openshell sandbox upload --no-git-ignore` copies the job into `/sandbox/security-agent/jobs/<random id>`. Benchmark
   repositories contain `.gitignore` files; without the flag, files they name would be left out.
3. `openshell sandbox exec -- security-agent synthetic sandbox run-job` stages the repository again inside the
   sandbox, deletes the upload, runs the scan and writes the result to `/sandbox/security-agent/results/<id>.json`.
4. `openshell sandbox download` brings the result back, and the host removes job and result from the sandbox.

The repository's instance id, the benchmark and the answer key never enter the sandbox.

OpenShell 0.0.106 occasionally leaves an exec hanging before its command starts, or returns from one while its command
still runs. The host therefore does not rely on the exec: the job writes a marker when it starts and touches it while it
runs, and the host checks the marker and the result file with short execs. A job that does not start within two
minutes, or whose marker goes stale, is retried once; after that the scan counts as incomplete, and `bench run` scans
it again when resumed.

Each job carries a hash of the host's `security_agent` code, and the sandbox refuses jobs from other code. After
changing anything in `src/security_agent/`, run `sandbox/sandbox.sh create` again: it builds the image from the
current code.

## Deploying an approved agent

From the repository root:

```bash
hatch run synthetic:deploy --sandbox security-agent --candidate agents/synthetic/looped --approved-by "<name>"
hatch run synthetic:scan --sandbox security-agent path/to/repository
```

`deploy` checks the candidate against the contract, runs its contract test in the sandbox, shows its files and asks
for approval. It installs the candidate at `/sandbox/.security-triage/deployed/` with a record of who approved it and
when, replacing the agent deployed before. `scan` without `--candidate` uses that agent.

## Limits

- One sandbox runs the scans of one experiment: 8 at a time, as many as the model server's parallel slots.
- The sandbox has no GPU and needs none: the model runs on the host.
- Sandboxes do not survive a restart of the OpenShell gateway. `sandbox.sh create` makes a new one.
