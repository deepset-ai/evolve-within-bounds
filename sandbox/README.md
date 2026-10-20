# Sandbox

Both benchmarks' agents run inside an [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) sandbox, created through
[NVIDIA NemoClaw](https://github.com/NVIDIA/NemoClaw):

- **Synthetic custom components:** the evaluation scans (`hatch run synthetic:bench run --sandbox …`); the
  self-improvement loop's measurements, and the optimizer's tries of its own code: `run_tool`, `trial_scan` and the
  contract test (`hatch run synthetic:loop run --sandbox …`); the deployed agent, after a person approves it (`hatch
  run synthetic:deploy …`, then `hatch run synthetic:scan --sandbox …`).
- **PrimeVul:** every function the agents judge, for the evaluation (`hatch run primevul:run --sandbox …`) and for the
  prompt loop's measurements (`hatch run primevul:loop run --sandbox …`).

The host keeps the benchmarks, their answer keys, the loops and the optimizers, and never runs a candidate's code. For
each piece of work it uploads a job, runs it in the sandbox and downloads the result
([`security_agent.sandbox`](../src/security_agent/sandbox.py)). Inside the sandbox, the model is reached through
OpenShell's managed inference route, `https://inference.local/v1`, which NemoClaw points at the model server on the
host. The PrimeVul agents also reach their knowledge base: Qdrant on the host, as `host.openshell.internal:6333`, for
reads only. The sandbox's policy allows no other network destination.

## What is here

| | |
|---|---|
| [`sandbox.sh`](sandbox.sh) | `setup`, `create`, `status`, `destroy` |
| [`security-triage/`](security-triage/) | the NemoClaw agent: the sandbox image with this repository's package and the knowledge base's retrieval models installed, its entrypoint, its policy and its manifest |
| [`nemoclaw.patch`](nemoclaw.patch) | registers the agent with NemoClaw's onboarding |

**Pinned:** NemoClaw at [`2cf1ecd69`](https://github.com/NVIDIA/NemoClaw/commit/2cf1ecd69e81ce12a44b8bd60dca8f4b7d76a7b9),
with OpenShell 0.0.106, the only version that commit accepts. Keep both: OpenShell 0.1 removed the managed inference
route that the sandbox uses.

**Why a patch:** `nemoclaw onboard --agent <name>` only accepts agents that NemoClaw's onboarding code knows. The patch
adds one, `security-triage`, as a one-shot terminal agent with one inference role and no dashboard or messaging. The
agent directory itself (`security-triage/`) is copied into the NemoClaw checkout by `sandbox.sh create`.

## Run it

Needs Docker, Node.js 22.19 or newer, and a model server from [`serving/`](../serving/), started first. For PrimeVul,
also Qdrant with the knowledge base ([`docs/primevul.md`](../docs/primevul.md), step 2):

```bash
hatch run serving:flash-next start   # PrimeVul; for the synthetic benchmark: hatch run serving:super-vl start
sandbox/sandbox.sh setup     # NemoClaw at the pin with the patch, OpenShell 0.0.106, the nemoclaw command
sandbox/sandbox.sh create    # builds the image and creates the sandbox "security-agent" (about 6 minutes)
```

`create` routes the sandbox's model calls to the model it is given in `MODEL`, Flash-Next by default. For the
synthetic benchmark, whose numbers come from Super VL, create it with `MODEL=nemotron-3.5-super-vl sandbox/sandbox.sh
create`.

The model server listens on loopback, and also on the gateway of OpenShell's Docker bridge when that bridge exists;
that is where the sandbox's inference route sends model calls. Qdrant does the same when started with `hatch run
primevul:qdrant up -d` ([`serving/qdrant/`](../serving/qdrant/)). Neither address is reachable from the network. The
bridge is created with the first sandbox, so a server started before needs one restart:

- the model server: `create` says so; `hatch run serving:<model> stop`, then `start`;
- Qdrant: `hatch run primevul:qdrant up -d` again. It recreates the container with the bridge address and keeps the
  knowledge base.

With Docker Desktop (macOS), the bridge lives inside Docker's VM, which forwards `host.openshell.internal` to the host's
loopback: neither server needs a restart.

`sandbox/sandbox.sh status` shows the sandbox, the inference route, and whether the model server and Qdrant answer on
the bridge.

Then pass `--sandbox security-agent` to the commands. The runbooks, [`docs/synthetic.md`](../docs/synthetic.md) and
[`docs/primevul.md`](../docs/primevul.md), do this everywhere.

Settings, as environment variables: `SANDBOX` (the sandbox's name, default `security-agent`), `MODEL` (the served
model name, default `qwen3.8-flash-next`; `nemotron-3.5-super-vl` for Super VL, `nemotron-3.5-lightning` for NIM) and
`NEMOCLAW_DIR` (default `~/NemoClaw-security-agent`).

## How a job runs

1. The host writes a job directory: `job.json` (the kind of job, the model settings) and the files the job needs.
2. `openshell sandbox upload --no-git-ignore` copies the job into `/sandbox/security-agent/jobs/<random id>`.
   Benchmark repositories contain `.gitignore` files; without the flag, files they name would be left out.
3. `openshell sandbox exec -- security-agent <benchmark> sandbox run-job` runs the job, deletes the upload and writes
   the result to `/sandbox/security-agent/results/<id>.json`.
4. `openshell sandbox download` brings the result back, and the host removes job and result from the sandbox.

OpenShell 0.0.106 occasionally leaves an exec hanging before its command starts, or returns from one while its command
still runs. The host therefore does not rely on the exec: the job writes a marker when it starts and touches it while it
runs, and the host checks the marker and the result file with short execs. A job that does not start within two
minutes, or whose marker goes stale, is retried once; after that it counts as not done, and the command does it again
when resumed.

Each job carries a hash of the host's `security_agent` code, and the sandbox refuses jobs from other code. After
changing anything in `src/security_agent/`, run `sandbox/sandbox.sh create` again: it builds the image from the
current code.

### A scan (synthetic)

The host stages the repository: a copy without files that would give the answer away, with fixed metadata, at a random
path. The job holds the candidate and the staged repository. Inside, `run-job` stages the repository again, deletes the
upload and scans. The repository's instance id, the benchmark and the answer key never enter the sandbox.
([`security_agent.synthetic.sandbox`](../src/security_agent/synthetic/sandbox.py))

### A function (PrimeVul)

The job is `job.json` alone: the agent file and the user message with the function. The function's id, its pair, its
labels and the benchmark file never enter the sandbox. The agent file is rewritten for the sandbox, and nothing else in
it changes: the agent's and the knowledge-base sub-agent's model go through the inference route, and the tool's Qdrant
is `http://host.openshell.internal:6333`. Inside, `run-job` loads the agent and judges the function exactly as `primevul
run` does without a sandbox, and returns the function's record: answer, verdict, steps, trajectory, tokens, and the
seconds of the judgement itself, without loading the agent.
([`security_agent.primevul.sandbox`](../src/security_agent/primevul/sandbox.py))

- **Before a run** the host asks the sandbox once whether the agent reaches the model (a one-token request) and the
  knowledge base (a search without the sub-agent). The knowledge-base tool reports a missing knowledge base instead of
  failing, so without this check a run would quietly go on without it.
- **The retrieval models** (the dense embedder, the BM25 encoder and the cross-encoder) are installed in the image at
  the agents' pinned revisions and load offline. They run on the CPU, as on the host.
- **Qdrant, read-only:** the policy allows `GET` on the collections and `POST` to the endpoints that search, scroll,
  count and fetch points; nothing that writes or deletes.
- **A function whose job fails** in the sandbox itself, not in the agent, is not stored. It counts as a parse error,
  `run` says so and exits with 1, and the same command run again judges what is missing. The prompt loop measures such
  functions again, like those lost to a model-server outage.

## Deploying an approved agent (synthetic)

From the repository root:

```bash
hatch run synthetic:deploy --sandbox security-agent --candidate agents/synthetic/looped --approved-by "<name>"
hatch run synthetic:scan --sandbox security-agent path/to/repository
```

`deploy` checks the candidate against the contract, runs its contract test in the sandbox, shows its files and asks
for approval. It installs the candidate at `/sandbox/.security-triage/deployed/` with a record of who approved it and
when, replacing the agent deployed before. `scan` without `--candidate` uses that agent.

## Limits

- One sandbox runs one experiment at a time: 8 synthetic scans at a time, as many as the model server's parallel
  slots, or 4 PrimeVul functions.
- The sandbox has no GPU and needs none: the model runs on the host.
- A PrimeVul job loads the agent and its retrieval models for each function; the time it takes is not counted in the
  function's seconds.
- Sandboxes do not survive a restart of the OpenShell gateway. `sandbox.sh create` makes a new one.

## Troubleshooting

- **`create` stops with "Sandbox containers cannot reach the gateway … A host firewall may be blocking traffic from
  the OpenShell Docker bridge":** a host firewall such as ufw drops traffic from the bridge to the host. Add the rule
  NemoClaw prints, for OpenShell's gateway on port 8080, then run `create` again. For PrimeVul, add the same rule for
  Qdrant's port, 6333.
