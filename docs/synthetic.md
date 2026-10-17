# Runbook: the synthetic custom-component benchmark

This runbook reruns our synthetic results on one DGX Spark: serve the model, create the OpenShell sandbox, scan the
benchmark with the two agents, run the self-improvement loop, and deploy an approved agent into the sandbox. Every scan
runs inside the sandbox.

## What is being measured

**The benchmark** ([`data/synthetic-components/`](../data/synthetic-components/)) has 50 pairs of small repositories of
custom Haystack components. One repository of each pair has a planted vulnerability; the other, its safe twin, is the
same code with the defect fixed. A pair is right when the agent reports a finding within 2 lines of the planted lines in
the vulnerable repository, whatever its CWE, and none at the corresponding lines of the safe twin. The agent scans one
whole repository at a time and never knows which of the two it is looking at.

The pairs are split by repository into 25 training, 13 validation and 12 test pairs
([`split.json`](../src/security_agent/synthetic/config/split.json)).

**The two agents** ([`agents/synthetic/`](../agents/synthetic/)) are Haystack pipelines around a Haystack `Agent`:

- **seed:** the starting point, deliberately weak. The agent gets the repository's file list, a size-capped
  `read_file`, Monty's sandboxed `run_python`, a short generic prompt and low limits.
- **looped:** what the self-improvement loop made of the seed. The optimizer, an agent on the same model, wrote three
  pipeline steps (`guards`, `hunter`, `verifier`) and three tools for the agent (`search`, `outline`, `rare`), about
  1,500 lines of Python, rewrote the system prompt and raised the agent's limits. Of the loop's candidates, it had the
  most validation pairs right (counted over all benchmarks our loop ran on, see below).

**Our numbers** (Qwen3.8 Flash-Next, one run each):

| Pairs right | seed | looped |
|---|---|---|
| test (12 pairs) | 7 (58.3%) | 8 (66.7%) |
| validation (13 pairs) | 7 (53.8%) | 9 (69.2%) |
| tokens per repository scan, test | 45k | 81k |

One pair is 8 points on 12 pairs, and runs vary: expect a rerun to land within one or two pairs of these. Most prompt
tokens are served from the model server's prefix cache, because the agent resends its conversation at every step.

**How our run differs from a rerun:**

Our loop trained on these 12 synthetic training pairs together with 24 pairs from two internal benchmarks that we
cannot publish. The looped agent comes from that run. A loop run from this repository trains on the 12 synthetic
pairs alone, so it will produce different candidates.


## Requirements

- An NVIDIA DGX Spark with Docker and the NVIDIA Container Toolkit, Node.js 22.19 or newer, and
  [Hatch](https://hatch.pypa.io/latest/install/).
- About 140 GB of disk for the model and the server image.

All commands run from the repository root.

## 1. Serve the model

```bash
hatch run serving:flash-next setup   # once: recipe, checkpoint (about 130 GB), image
hatch run serving:flash-next start   # about 4 to 7 minutes until it answers
hatch run serving:smoke              # optional: 8 checks against the server
```

Details in [`serving/qwen3.8-flash-next/`](../serving/qwen3.8-flash-next/). The server takes 8 requests at a time;
the scans below run 8 repositories in parallel to match.

## 2. Create the sandbox

```bash
sandbox/sandbox.sh setup    # once: NemoClaw at the pinned commit with our patch, OpenShell 0.0.106
sandbox/sandbox.sh create   # about 6 minutes: builds the image and creates the sandbox "security-agent"
```

The sandbox reaches the model server through OpenShell's Docker bridge, which the first sandbox creates. If the server
was started before that, `create` says so: restart it once (`hatch run serving:flash-next stop`, then `start`).
`sandbox/sandbox.sh status` checks the route. How the sandbox works, and what leaves it: [`sandbox/`](../sandbox/).

## 3. Prepare the benchmark

```bash
hatch run synthetic:bench prepare
```

This materializes the 112 repositories (50 pairs, plus 12 placebo repositories for some pairs) into `work/synthetic/`,
with the answer key next to them. The answer key stays on the host; the sandbox only ever sees one staged repository at
a time.

## 4. Scan with both agents

```bash
hatch run synthetic:bench run --candidate agents/synthetic/seed   --split test --sandbox security-agent
hatch run synthetic:bench run --candidate agents/synthetic/looped --split test --sandbox security-agent
```

Each command scans the repositories of the 12 test pairs, scores them with the benchmark's own scorer and prints the
metrics over those pairs; `paired_localization_accuracy` is the share of pairs right. The run directory under
`runs/synthetic/` keeps every scan's record (the agent's conversation, its tool calls, each step's input and output),
`predictions.jsonl`, the full `score.json` and `summary.json`. A scan takes a few minutes; with 8 in parallel, a split
takes well under an hour per agent.

An interrupted run resumes where it stopped: pass the same `--run-dir`. Scans the model server dropped are scanned
again.

`--split val` scans the validation pairs, `--pair <id>` a single pair. Nemotron 3.5 Lightning on NIM works too
(`--model-config model.lightning.yaml`, and `MODEL=nemotron-3.5-lightning` for `sandbox.sh create`), but our numbers
are from Flash-Next.

## 5. Run the self-improvement loop

Try the mechanics first, on two training pairs and one candidate:

```bash
hatch run synthetic:loop run --smoke --sandbox security-agent
```

Then the experiment as configured in [`loop.yaml`](../src/security_agent/synthetic/config/loop.yaml):

```bash
hatch run synthetic:loop run --sandbox security-agent
hatch run synthetic:loop status --run-dir runs/synthetic/loop/opt-1   # in a second terminal
```

What happens (details in [`optimize/loop.py`](../src/security_agent/optimize/loop.py), the loop the benchmarks
share, and [`synthetic/task.py`](../src/security_agent/synthetic/task.py), what is specific to this one):

1. **Pre-registration.** The rules, the 12 training pairs, the starting candidate and the budget go to
   `preregistration.json` before anything is measured.
2. **The starting candidate** (the seed) is measured on the training pairs.
3. **Turns.** The optimizer, a Haystack Agent on the same model, gets the outcomes so far and a failure digest for each
   training pair the best candidate gets wrong. It can read what the scanning agent did on a training pair
   (`read_reasoning`), try a tool or step it wrote on one (`run_tool`) and scan one with the whole draft
   (`trial_scan`), both inside the sandbox. It submits one candidate per turn.
4. **Gates.** A candidate is measured on half the training pairs first and stopped there if it is clearly behind. It
   is eligible only if it copies no training answers, completes its scans, stays within 6 estimated GPU-minutes and 10
   findings per repository on average, and its steps rarely fail. An eligible candidate becomes the next turn's starting
   point only if it gets more pairs right, or as many with fewer findings or less GPU time.
5. **Stop** after 15 candidates, 40 GPU-hours, or when the optimizer finishes. `decision.json` lists every candidate.

The validation pairs never enter the loop. Pick among the candidates afterwards:

```bash
hatch run synthetic:bench run --candidate runs/synthetic/loop/opt-1/candidates/<c00N-...> --split val --sandbox security-agent
```

Take the one with the most validation pairs right, and look at the test pairs once, with that candidate only.

The run directory keeps every turn's conversation (`turns/`), every candidate (`candidates/`) and every measurement
(`measure/`), and resumes when started again with the same `--run-dir`.

## 6. Approve and deploy

```bash
hatch run synthetic:deploy --sandbox security-agent --candidate agents/synthetic/looped --approved-by "<your name>"
hatch run synthetic:scan --sandbox security-agent path/to/a/repository
```

`deploy` checks the candidate against the contract, runs its contract test in the sandbox, lists its files and asks
you to approve it. It then installs the candidate in the sandbox with a record of the approval. `scan` scans any
repository with the deployed agent and prints its findings; the full result, with the agent's conversation, goes to
`runs/synthetic/`.

## Without the sandbox

Without `--sandbox`, scans and the optimizer's code run on the host, in the command's own process. The optimizer's code
is checked before it runs: no file, process or network modules, no `open`, `eval` or `exec`. That check is not a
security boundary; the sandbox is.

## Troubleshooting

- **Scans end incomplete with connection errors:** the model server crashed or is restarting. Scans wait for it up to a
  limit, then count as incomplete; rerun with the same `--run-dir`.
- **`sandbox.sh status` says the model server is not reachable on the bridge:** restart the server (step 2).
- **The sandbox is gone** (after a restart of the OpenShell gateway): `sandbox/sandbox.sh create`.
- **"the sandbox runs security_agent …, the host …":** the code changed since the sandbox was created; `sandbox/sandbox.sh
  create` again.
