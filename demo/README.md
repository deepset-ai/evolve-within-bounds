# Demo: one iteration of the self-improvement loop, deployed after a person approves

The talk's live demo, on one NVIDIA DGX Spark with nothing leaving the machine. In about 3 to 5 minutes:

1. the optimizer, an agent on Qwen3.8 Flash-Next, improves the repository scan agent on a training pair of the synthetic
   benchmark, through one short turn of the loop;
2. the candidate it submits is scanned on that pair inside the OpenShell sandbox and has to clear the loop's gates;
3. a person approves it, and it is deployed into the sandbox;
4. the deployed agent scans a repository from the validation pairs, which nothing in the loop has seen.

It is the loop of [`docs/synthetic.md`](../docs/synthetic.md), cut down in size only (see below). Every scan, and every
line of the optimizer's code, runs inside the sandbox.

## Before the talk

The setup of the runbook, steps 1 to 3, then the demo's preparation. With the model, the images and the benchmark already
downloaded, on one DGX Spark:

```bash
hatch run serving:flash-next start   # about 5½ minutes until it answers
sandbox/sandbox.sh create            # about 2 minutes: the sandbox "security-agent"
hatch run synthetic:bench prepare    # seconds
demo/prepare.sh                      # about 1½ minutes: pre-registers the experiment, measures the seed on the pair
demo/preflight.sh                    # ends with "ready"
```

Every run starts from a copy of what `prepare.sh` measured, so it is done once, and again only after changing
[`demo.yaml`](demo.yaml).

## Running

```bash
demo/preflight.sh                              # model server, sandbox, its route to the model, benchmark, preparation
demo/run_demo.sh --approved-by "Your Name"     # the demo; type 'yes' when it asks to deploy
```

It prints:

1. **the benchmark, the training pair and the bounds;**
2. **the starting point:** the seed's result on the pair, measured by `prepare.sh`, and why it failed;
3. **the optimizer's turn, live:** one line per tool call (reading what the agent did, editing the draft, validating,
   submitting), with the time;
4. **the candidate's measurement on the pair:** why the optimizer made the change, which files changed and a few of the
   lines it wrote, pairs right, findings, estimated GPU time, and whether it cleared every gate;
5. **the approval:** the candidate is checked against the contract and its code's contract test runs in the sandbox;
   then a prompt to approve it, and the deployment, with who approved it and when recorded in the sandbox;
6. **the deployed agent scanning a repository it has never seen,** with its findings and whether one of them is the
   planted defect.

Each section ends with how long it took, and the last line with the total. Three rehearsals took 2:53, 2:54 and 5:09:
the optimizer's turn about a minute, the measurement 1¼ to 3½ minutes, the approval and deployment seconds (plus the
time it takes to type `yes`), the final scan about half a minute. The experiment's directory
(`runs/demo/live/`) keeps everything the loop keeps: the optimizer's conversation, the candidate, the scans.

**Reading it.** With one training pair, a candidate gets the pair right or wrong; a candidate that "gets better" on one
pair proves nothing about it. What the demo shows is the mechanics within the bounds: the optimizer reads what the agent
did, changes it, the change is measured in the sandbox and gated, a person decides, and only then is it deployed. If the
candidate does not clear the gates, the demo offers the agent our full loop run produced
([`agents/synthetic/looped`](../agents/synthetic/looped/)) for approval instead.

## How it differs from the full loop

Only in size ([`demo.yaml`](demo.yaml) against [`loop.yaml`](../src/security_agent/synthetic/config/loop.yaml)):

| | demo | full loop |
|---|---|---|
| training pairs | 1, chosen for short scans, and one the seed gets wrong | 12 |
| the seed's measurement | before the demo (`prepare.sh`) | at the start of the run |
| optimizer turns | 1, of at most 12 tool calls | up to 15, of at most 60 tool calls |
| optimizer's reasoning per reply | 1,024 tokens | 4,096 tokens |
| `trial_scan` and `run_tool` | not offered | offered |

The optimizer's prompt is the full loop's, with a paragraph added that says the turn is short and asks it to keep the agent's limits as they are. The gates, the leakage
check, the contract, the sandbox and the deployment are the same.

## Recording and replaying a run

```bash
demo/record.sh --yes --approved-by "Your Name"   # records run_demo.sh, with timing, into runs/demo/recording
demo/replay.sh                                   # plays it back in the terminal as it ran
demo/replay.sh 1 20                              # never pausing more than 20 seconds (the measurement waits longest)
```

With `--yes` the recording shows the approval prompt answered, marked as given in advance. `replay.sh` needs
`scriptreplay` from util-linux: on the Spark it is there; on macOS, `brew install util-linux`.

## Choosing another pair

[`demo.yaml`](demo.yaml) names the training pair (`train_pair`) and the repository of the final scan (`scan_instance`).
Pick a training pair whose scans are short and that the seed gets wrong, and a repository from the validation pairs
(`src/security_agent/synthetic/config/split.json`) whose scan is short; then run `demo/prepare.sh` again.
