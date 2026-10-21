# Runbook: the synthetic custom-component benchmark

This runbook reruns our synthetic results on one DGX Spark: serve the model, create the OpenShell sandbox, scan the
benchmark with the two agents, run the self-improvement loop, and deploy an approved agent into the sandbox. Every scan
runs inside the sandbox; only the NeMo Gym rollouts of step 7 run on the host.

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
- **looped:** what the self-improvement loop made of the seed. The optimizer, an agent on the same model, wrote a
  long system prompt that names vulnerability classes and their safe forms, a `search` tool, and two pipeline steps:
  `verifier`, which retracts findings on code a control makes safe, and `hunter`, whose notes never reach the agent
  (see its `pipeline.yaml`). It also raised the agent's limits. Of the loop's candidates, it had the most validation
  pairs right (counted over all benchmarks our loop ran on, see below).

**Our numbers** (Nemotron 3.5 Super VL, one run each):

| Pairs right | seed | looped |
|---|---|---|
| test (12 pairs) | 4 (33.3%) | 9 (75.0%) |
| validation (13 pairs) | 8 (61.5%) | 10 (76.9%) |
| fixed twins flagged, test | 7 of 12 | 1 of 12 |
| tokens per repository scan, test | 18k | 25k |

One pair is 8 points on 12 pairs, and runs vary: expect a rerun to land within one or two pairs of these. What the
numbers do and do not show, and how they were produced: [`results/synthetic.md`](../results/synthetic.md).

**How our run differs from a rerun:**

- **Data.** Our loop trained on 24 of these synthetic training pairs together with 48 pairs from two benchmarks we
  can't publish, and was picked on their validation pairs too. A loop run from this repository trains on the 24
  synthetic pairs alone, so it will produce different candidates.
- **Two stages.** Our loop first accepted a candidate only if it got at least 3 more validation pairs right than the
  best so far, and stopped after three candidates without that, none accepted. It then went on as this repository's
  loop does, from the best of those three on the training pairs, and we picked the looped agent afterwards on
  validation. [`results/synthetic.md`](../results/synthetic.md) has the details.


## Requirements

- An NVIDIA DGX Spark with Docker and the NVIDIA Container Toolkit, Node.js 22.19 or newer, and
  [Hatch](https://hatch.pypa.io/latest/install/).
- About 100 GB of disk for the model and the server image.

All commands run from the repository root.

## 1. Serve the model

```bash
hatch run serving:super-vl setup     # once: image and checkpoint (about 70 GB)
hatch run serving:super-vl start     # about 13 minutes until it answers
hatch run serving:smoke              # optional: 8 checks against the server
```

Details in [`serving/nemotron-3.5-super-vl/`](../serving/nemotron-3.5-super-vl/). The server takes 8 requests at a
time; the scans below run 8 repositories in parallel to match.

## 2. Create the sandbox

```bash
sandbox/sandbox.sh setup    # once: NemoClaw at the pinned commit with our patch, OpenShell 0.0.106
MODEL=nemotron-3.5-super-vl sandbox/sandbox.sh create   # about 6 minutes: the image and the sandbox "security-agent"
```

`MODEL` is the model the sandbox's inference route serves; the default is Flash-Next, which PrimeVul uses.

The sandbox reaches the model server through OpenShell's Docker bridge, which the first sandbox creates. If the server
was started before that, `create` says so: restart it once (`hatch run serving:super-vl stop`, then `start`).
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

`--split val` scans the validation pairs, `--pair <id>` a single pair. Qwen3.8 Flash-Next and Nemotron 3.5 Lightning on
NIM work too (`--model-config model.flash-next.yaml` or `model.lightning.yaml`, and the model's name in `MODEL` for
`sandbox.sh create`), but our numbers are from Super VL.

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

1. **Pre-registration.** The rules, the 24 training pairs, the starting candidate and the budget go to
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

## 7. Roll out the agents with NeMo Gym

The same agents as [NeMo Gym](https://github.com/NVIDIA-NeMo/Gym) rollouts ([`gym/`](../gym/)). Super VL must be up
(step 1) and the benchmark prepared (step 3).

```bash
hatch run synthetic:gym export --split test   # work/gym/synthetic/test-all.jsonl: the 24 repositories of the 12 test pairs
hatch run gym:start-synthetic                   # the servers; the first start builds their environments
```

The first start builds an environment for each server in `work/gym/venvs/`, a few minutes; later starts take seconds.

In a second terminal, once the first reports `All 6 / 6 servers ready`:

```bash
hatch run gym:collect-synthetic --agent synthetic_seed   --input work/gym/synthetic/test-all.jsonl --output runs/synthetic/gym/seed-test.jsonl
hatch run gym:collect-synthetic --agent synthetic_looped --input work/gym/synthetic/test-all.jsonl --output runs/synthetic/gym/looped-test.jsonl
```

Each row is one repository, the vulnerable one or the fixed twin of a pair. The agent server scans it with our scanner,
unchanged, and sends every model call through Gym's model server. The resources server scores the findings with the
benchmark's own scorer and answer key: the reward is 1 when the vulnerable repository has a finding on the planted
lines, or the fixed twin has none there. `collect` then prints the metrics `bench run` prints, over the pairs whose two
repositories it scanned: paired localization accuracy first. The placebo repositories that `bench run` also scans are
left out; they do not enter these metrics. `--num-repeats N` scans every repository N times; the metrics are computed
per repeat and averaged. Stop the servers with Ctrl-C in the first terminal. `hatch run gym:test` runs the servers'
own tests.

**Not in the sandbox.** Gym's agent server runs the scanner in its own process, as `bench run` does without
`--sandbox`, so the looped agent's own code runs on the host (see below). A rollout's model calls have to go through
Gym's model server; from inside the sandbox they would go straight to the model server it was created with.

## Without the sandbox

Without `--sandbox`, scans and the optimizer's code run on the host, in the command's own process. The optimizer's code
is checked before it runs: no file, process or network modules, no `open`, `eval` or `exec`. That check is not a
security boundary; the sandbox is.

## Troubleshooting

- **Scans end incomplete with connection errors:** the model server crashed or is restarting. Scans wait for it up to a
  limit, then count as incomplete; rerun with the same `--run-dir`.
- **`sandbox.sh status` says the model server is not reachable on the bridge:** restart the server (step 2).
- **The sandbox is gone** (after a restart of the OpenShell gateway): `MODEL=nemotron-3.5-super-vl sandbox/sandbox.sh
  create`.
- **"the sandbox runs security_agent …, the host …":** the code changed since the sandbox was created; create it again
  (step 2).
- **`gym:start-synthetic` stops with `address already in use` on port 11000:** another service holds the port of Gym's
  head server. Pick a free one and pass it to both commands: `hatch run gym:start-synthetic ++head_server.port=11100`,
  and the same `++head_server.port=11100` after `gym:collect-synthetic`.
- **Gym's servers keep running after `gym:start-synthetic` ended:** stop the processes that run from `work/gym/venvs/`,
  for example `pkill -f work/gym/venvs`.
