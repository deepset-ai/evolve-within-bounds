# Demo: one iteration of the self-improvement loop, deployed after a person approves

The talk's live demo, on one NVIDIA DGX Spark with nothing leaving the machine. In about 3 to 5 minutes:

1. the optimizer, an agent on Qwen3.8 Flash-Next, improves the repository scan agent on a training pair of the synthetic
   benchmark, through one short turn of the loop;
2. the candidate it submits is scanned on that pair inside the OpenShell sandbox and has to clear the loop's gates;
3. a person approves it, and it is deployed into the sandbox;
4. the deployed agent scans a repository from the validation pairs, which nothing in the loop has seen.

It is the loop of [`docs/synthetic.md`](../docs/synthetic.md), cut down in size, with the optimizer at temperature 0
(see below). Every scan, and every line of the optimizer's code, runs inside the sandbox.

## Before the talk

The setup of the runbook, steps 1 to 3, then the demo's preparation. With the model, the images and the benchmark already
downloaded, on one DGX Spark:

```bash
hatch run serving:flash-next start   # about 5½ minutes until it answers
sandbox/sandbox.sh create            # about 2 minutes: the sandbox "security-agent"
hatch run synthetic:bench prepare    # seconds
demo/prepare.sh                      # about 5½ minutes: pre-registers the experiment, measures the seed on the pair
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
2. **the starting point:** the seed's result on the pair, measured by `prepare.sh`, and why it failed; the planted
   lines in both twins; and the seed's trace on the twin where it failed: its steps, the reasoning that led to the
   failure, and its report. The trace follows the failure mode: the fixed twin when the seed only flagged it, the
   vulnerable repository when it missed the defect, reported the wrong lines or lost its finding;
3. **the optimizer's turn, live:** first what the optimizer is given (the agent's files, the failure, the seed's
   traces on request), then one line per tool call (reading the trace, editing the draft, validating, submitting),
   with the time;
4. **what the optimizer changed:** its reason, then the change as git shows it: `git diff --stat`'s summary, and the
   diff in git's colours, cut after 40 rows (the whole diff goes to `runs/demo/live/candidate.diff`);
5. **the candidate's measurement on the pair:** pairs right, findings, estimated GPU time, and whether it cleared every
   gate;
6. **the approval:** the candidate, if it became the new best (otherwise the agent our full loop run produced), is
   checked against the contract and its code's contract test runs in the sandbox; then a prompt to approve it, and
   the deployment, with who approved it and when recorded in the sandbox;
7. **the deployed agent scanning a repository it has never seen,** with its findings and whether one of them is the
   planted defect.

Each step shows how long it took, and the last line the total. Five rehearsals took 2:30 to 5:29, 3:47 in the middle:
the optimizer's turn about a minute, the measurement 1 to 4 minutes, the approval and deployment seconds (plus the
time it takes to type `yes`), the final scan about half a minute. The experiment's directory
(`runs/demo/live/`) keeps everything the loop keeps: the optimizer's conversation, the candidate, the scans.

**Reading it.** With one training pair, a candidate gets the pair right or wrong; a candidate that "gets better" on one
pair proves nothing about it. What the demo shows is the mechanics within the bounds: the optimizer reads what the agent
did, changes it, the change is measured in the sandbox and gated, a person decides, and only then is it deployed. Only a
candidate that becomes the new best is offered for approval: it clears every gate and gets more pairs right than the
seed, or as many with fewer findings or less GPU time. Otherwise the demo says why and offers the agent our full loop run
produced ([`agents/synthetic/looped`](../agents/synthetic/looped/)) instead.

## How it differs from the full loop

In size, and in the optimizer's temperature ([`demo.yaml`](demo.yaml) against
[`loop.yaml`](../src/security_agent/synthetic/config/loop.yaml)):

| | demo | full loop |
|---|---|---|
| training pairs | 1, chosen for short scans, and one the seed gets wrong | 12 |
| the seed's measurement | before the demo (`prepare.sh`) | at the start of the run |
| optimizer turns | 1, of at most 12 tool calls | up to 15, of at most 60 tool calls |
| optimizer's reasoning per reply | 1,024 tokens | 4,096 tokens |
| optimizer's temperature | 0 | 0.6 |
| `trial_scan` and `run_tool` | not offered | offered |

The optimizer's prompt is the full loop's, with a paragraph added that says the turn is short and asks it to keep the agent's limits as they are. The gates, the leakage
check, the contract, the sandbox and the deployment are the same.

## Recording and replaying a run

```bash
demo/replay.sh                                   # plays the recorded run back in the terminal, as it ran
demo/replay.sh 2 20                              # twice as fast, never pausing more than 20 seconds
demo/record.sh --yes --approved-by "Your Name"   # on the Spark: records run_demo.sh, with timing, into demo/recording
```

[`recording/`](recording/) holds a run recorded on one DGX Spark (`session.log`, the terminal output, `timing.log`,
when each part of it appeared, and `candidate.diff`, the whole change the optimizer made), so the demo can be watched
without a Spark. `replay.sh` needs only Python 3; use a terminal at least 110 columns wide. The run was recorded with
`--yes`, but the replay stops at the approval prompt until you type `yes`, as the live run does, and leaves out the
recorded answer; without a terminal (output redirected) it plays as recorded. A new recording replaces the old one;
commit it to share it.

## Choosing another pair

[`demo.yaml`](demo.yaml) names the training pair (`train_pair`) and the repository of the final scan (`scan_instance`).
Pick a training pair that the seed gets wrong, whose scans are short, and whose fixed twin is safe beyond doubt: if the
seed's flag on the fixed twin is a fair concern, the optimizer has to talk the agent out of it, and often does not.
Pick a repository from the validation pairs (`src/security_agent/synthetic/config/split.json`) whose scan is short;
then run `demo/prepare.sh` again.
