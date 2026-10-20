# Runbook: PrimeVul

This runbook reruns our PrimeVul results on one DGX Spark: build the benchmark file and the knowledge base, serve the
model, create the OpenShell sandbox, measure the two agents on the test pairs, run the prompt loop that turned the seed
into the looped agent, and roll the agents out as a NeMo Gym environment. Every function is judged inside the sandbox;
only the NeMo Gym rollouts of step 7 run on the host.

## What is being measured

**The benchmark** is [PrimeVul](https://github.com/DLVulDet/PrimeVul), paired: each pair is a vulnerable C/C++
function from a real project and the same function after its fix. The agent judges one function at a time and never
sees its twin. A pair is right when it calls the vulnerable function vulnerable and the patched one benign; a model
that calls everything vulnerable gets no pair right. Our benchmark file has 100 training and 100 validation pairs, for
the self-improvement loop, and the 435 pairs of PrimeVul's paired test split. Our numbers are on the first 100 test
pairs.

**The two agents** ([`agents/primevul/`](../agents/primevul/)) are a Haystack `Agent` on Qwen3.8 Flash-Next that
answers with a JSON verdict: vulnerable or not, the CWE, the lines and a short rationale. Each has one tool,
`search_security_kb`, which asks a retrieval sub-agent about the knowledge base (step 2) and returns a short, cited
briefing. It never sees the code, so it can only help name the weakness.

- **seed:** a short prompt. Decide from the code alone; only for a function judged vulnerable, ask the tool once which
  CWE fits.
- **looped:** what two runs of the prompt loop made of the seed. They rewrote the system prompt (from 2,100 to 6,800
  characters) and the tool's description, nothing else. The new prompt walks through a procedure (inputs, the
  operations they reach, the checks on the way, then a verdict that must name the line and the missing check) and sets
  an evidence standard: no defect that rests on guesses about code the agent cannot see. Each run picked its candidate
  on the validation pairs.

**Our numbers** (first 100 test pairs, one run each):

| | seed | looped |
|---|---|---|
| pairs right | 16 | 21 |
| pairs whose patched function was called vulnerable, of the pairs with both verdicts | 75.0% | 58.5% |
| both twins called vulnerable | 65 | 46 |
| knowledge-base calls, for 200 functions | 351 | 297 |
| median seconds per function | 421 | 443 |

The two agents disagree on 23 pairs: the looped agent gets 14 of them right and the seed 9. With 100 pairs, one pair is
one point, and a rerun of the same agent lands within a few pairs. What the numbers do and do not show, and how they
were produced: [`results/primevul.md`](../results/primevul.md).

## Requirements

- An NVIDIA DGX Spark with Docker, [Hatch](https://hatch.pypa.io/latest/install/), and Node.js 22.19 or newer for
  NemoClaw.
- About 140 GB of disk for the model and the server image, and a few GB for the knowledge base's models and torch.

All commands run from the repository root.

## 1. Build the benchmark file

```bash
hatch run primevul:build    # downloads about 64 MB once, writes data/primevul/build/
hatch run primevul:verify   # every file's sha256 matches its manifest
```

The file the agents read is `data/primevul/build/primevul-loop.jsonl`. How it is built, and the rule for using it: the
validation and test pairs are only ever aggregated by scripts, nobody reads them. See
[`data/primevul/`](../data/primevul/).

## 2. Build the knowledge base

```bash
hatch run primevul:qdrant up -d                                  # Qdrant in Docker, on 127.0.0.1:6333
hatch run primevul:kb build                                      # about a minute, plus model downloads the first time
hatch run primevul:kb query "write past the end of a heap buffer"   # optional: retrieval only, no model server needed
```

The knowledge base holds 1,091 documents in one Qdrant collection:

- **969 CWE weakness definitions:** name and short description, from the MITRE CWE List
  ([`cwe_reference.json`](../src/security_agent/knowledge_base/cwe_reference.json)).
- **122 rules of the SEI CERT C Coding Standard:** each rule's title, the prose before its first code example, its risk
  assessment and the CWE ids it is tagged with, downloaded from the SEI's repository at a pinned commit.

Each document has a dense vector (BAAI/bge-small-en-v1.5) and a sparse BM25 one. When the agent calls
`search_security_kb`, a sub-agent from the Haystack agent pack (the Advanced RAG Agent) searches the collection with
both vectors at once, reranks the hits with a cross-encoder, can filter by source or identifier, and writes a briefing
that cites the documents it used. The briefing goes back to the agent framed as untrusted data, and all text was
scrubbed of role markers when it was indexed. The sub-agent runs on the same model server, with thinking off. Code:
[`src/security_agent/knowledge_base/`](../src/security_agent/knowledge_base/).

The sub-agent's prompt and the briefing's header also name NVD and ExploitDB: the tool was written for a larger
corpus. They are kept as the agents ran with them.

## 3. Serve the model

```bash
hatch run serving:flash-next setup   # once: recipe, checkpoint (about 130 GB), image
hatch run serving:flash-next start   # about 4 to 7 minutes until it answers
hatch run serving:smoke              # optional: 8 checks against the server, the thinking budget among them
```

Details in [`serving/qwen3.8-flash-next/`](../serving/qwen3.8-flash-next/). The agents call it at
`http://127.0.0.1:8000/v1` as `qwen3.8-flash-next`; inside the sandbox, through OpenShell's inference route.

## 4. Create the sandbox

```bash
sandbox/sandbox.sh setup    # once: NemoClaw at the pinned commit with our patch, OpenShell 0.0.106
sandbox/sandbox.sh create   # about 6 minutes: builds the image and creates the sandbox "security-agent"
```

The sandbox reaches the model server and Qdrant through OpenShell's Docker bridge, which the first sandbox creates. If
they were started before that, restart them once: `hatch run serving:flash-next stop`, then `start`, and `hatch run
primevul:qdrant up -d` again (the knowledge base stays). `sandbox/sandbox.sh status` checks both. The image holds the
knowledge base's retrieval models; the knowledge base itself stays in Qdrant on the host, which the sandbox may only
read. The synthetic benchmark uses the same sandbox. How it works, and what leaves it: [`sandbox/`](../sandbox/).

## 5. Measure both agents

Try the mechanics on one training pair first:

```bash
hatch run primevul:run --agent agents/primevul/seed --split train --pairs 1 --sandbox security-agent
```

Then the first 100 test pairs:

```bash
hatch run primevul:run --agent agents/primevul/seed   --split test --pairs 100 --sandbox security-agent
hatch run primevul:run --agent agents/primevul/looped --split test --pairs 100 --sandbox security-agent
```

First, a command with `--sandbox` checks that the agent reaches the model and the knowledge base from inside the
sandbox, and stops if it does not: the knowledge-base tool would otherwise answer every call with an error, and the run
would go on without it.

Each command judges the 200 functions, 4 at a time, and prints aggregates only: pairs right, the split rate (pairs whose
twins got different verdicts) times the right-way rate (of those, the right way round), false positives per function
and per pair, parse errors, and the counts of the failure labels (`missed_fix`: both twins called vulnerable,
`missed_bug`: both benign, `inverted`). A second line sums up how the agent spent its budget. One function takes a
few minutes (about 2.5 in our check on vLLM); our runs of 100 pairs took about 8 hours per agent.

The run directory, `runs/primevul/<agent>-test-100/`, keeps:

- `summary.json`: the metrics, the agent's configuration id, the thinking budget and the budget summary;
- `pairs.jsonl`: one label per pair;
- `tasks.json`: every function's record: the answer, the verdict, the steps and a compressed trajectory. The answers
  quote the functions, so for validation and test pairs, leave this file to the scripts.

An interrupted run resumes where it stopped: run the same command again. A function whose answer has no verdict gets
one more request for the final answer, with no tools; one that still has none counts as a parse error, and its pair as
wrong. A function the sandbox failed to judge (not the agent) is not stored: the command says so and exits with 1, and
running it again judges what is missing.

## 6. Run the prompt loop

Try the mechanics first, on two training pairs and one candidate (about 15 minutes):

```bash
hatch run primevul:loop run --smoke --sandbox security-agent
```

Then the experiment as configured in [`loop.yaml`](../src/security_agent/primevul/config/loop.yaml):

```bash
hatch run primevul:loop run --sandbox security-agent
hatch run primevul:loop status --run-dir runs/primevul/loop/opt-1   # in a second terminal
```

It is the loop the synthetic benchmark uses ([`optimize/loop.py`](../src/security_agent/optimize/loop.py)); what is
specific to PrimeVul is in [`primevul/task.py`](../src/security_agent/primevul/task.py):

1. **Pre-registration.** The rules, the first 100 training pairs, the starting agent (the seed) and the budget go to
   `preregistration.json` before anything is measured.
2. **The seed** is measured on the training pairs: 200 functions, about 8 hours.
3. **Turns.** The optimizer, a Haystack Agent on the same model, gets the outcomes so far and up to 12 failing pairs:
   both verdicts, the patch between the two functions, and what the agent did on each, down to the knowledge-base
   sub-agent's searches. It can read what the agent did on any training function (`read_reasoning`). It runs on the
   host and edits
   `agent.yaml`: the system prompt, the tool's description, the step budget, the output limit. The model, the
   temperature, the tool's settings and the JSON verdict stay fixed; `validate_candidate` checks that, and that the
   draft copies no code or function names from the training pairs. It submits one candidate per turn.
4. **Gates.** Each candidate is measured inside the sandbox, on half the training pairs first, and stopped there if it
   has 4 or more fewer pairs right than the seed on that half. It is eligible only if it loses no more functions to
   model-server errors or sandbox failures than the seed and stays within 1.5 estimated GPU-minutes per function, counting the tokens of the agent and of its
   sub-agent (the seed needs about 0.4). It becomes the next turn's starting point only if it gets more pairs right, or
   as many with fewer functions called vulnerable, or with less GPU time.
5. **Stop** after 3 candidates, 40 GPU-hours, or when the optimizer finishes. `decision.json` lists every candidate.

The validation pairs never enter the loop. Pick among the candidates afterwards, on the first 50 validation pairs:

```bash
hatch run primevul:run --agent agents/primevul/seed --split val --pairs 50 --sandbox security-agent
hatch run primevul:run --agent runs/primevul/loop/opt-1/candidates/<c00N-...> --split val --pairs 50 --sandbox security-agent
```

Take a candidate only if it has more validation pairs right than the seed, and look at the test pairs once, with that
candidate only. The run directory keeps every turn's conversation (`turns/`), every candidate (`candidates/`) and every
measurement (`measure/`), and resumes when started again with the same `--run-dir`.

## 7. Roll out the agents with NeMo Gym

The same agents as [NeMo Gym](https://github.com/NVIDIA-NeMo/Gym) rollouts ([`gym/`](../gym/)): a resources server that
scores each rollout with this repository's scoring, Gym's vLLM model server in front of Flash-Next, and one agent server
per agent that runs its agent file through Gym's Haystack harness. Flash-Next and Qdrant must be up (steps 2 and 3).

```bash
hatch run primevul:gym export --split test --pairs 100   # work/gym/primevul/test-100.jsonl
hatch run gym:start                                      # the servers; the first start builds their environments
```

The first start builds an environment for each server in `work/gym/venvs/`, a few minutes; later starts take seconds.

In a second terminal, once the first reports `All 6 / 6 servers ready`:

```bash
hatch run gym:collect --agent primevul_seed   --input work/gym/primevul/test-100.jsonl --output runs/primevul/gym/seed-test-100.jsonl
hatch run gym:collect --agent primevul_looped --input work/gym/primevul/test-100.jsonl --output runs/primevul/gym/looped-test-100.jsonl
```

`collect` prints the key metrics: paired accuracy, the false positive rate per pair, the parse-error rate, the split and
right-way rates, and the mean reward, which is the share of functions judged right. Next to the rollouts, Gym writes the
full metrics (`*_aggregate_metrics.json`). `--num-repeats N` judges every function N times; paired accuracy is computed
for each repeat and averaged. Stop the servers with Ctrl-C in the first terminal. `hatch run gym:test` runs the servers'
own tests.

**What is the same as `primevul run`, and what is not.** The agent files (prompt, tool, budgets), the user message, the
thinking budget, the knowledge-base tool and the scoring are the same. Gym's harness has no fallback for a missing
answer: our runner asks once more when a reply has no verdict, and Gym's harness does not, so expect a few more parse
errors. Our reported numbers come from `primevul run`.

**Not in the sandbox.** Gym's agent server runs the agent files in its own process, and a rollout's model calls have to
go through Gym's model server; from inside the sandbox they would go straight to the model server it was created with.

## Without the sandbox

Without `--sandbox`, `run` and `loop run` judge every function in the command's own process, with the same agent file,
the same model and the same knowledge base. The agents have no code of their own, so a candidate of the prompt loop
changes text and budgets only; the sandbox keeps the agent, which reads untrusted code and untrusted briefings, away
from the host.

## Troubleshooting

- **Every briefing says "Cannot reach Qdrant" or "No knowledge base":** the tool reports instead of failing, so a run
  without `--sandbox` goes on without it. Start Qdrant and build the knowledge base (step 2); `kb query` checks both.
- **`run --sandbox` stops: "the knowledge base at http://host.openshell.internal:6333 does not answer":** Qdrant does not
  listen on OpenShell's bridge. Run `hatch run primevul:qdrant up -d` again once the sandbox exists (step 4);
  `sandbox/sandbox.sh status` checks it.
- **`run --sandbox` stops: "the model does not answer at https://inference.local/v1":** restart the model server once
  the sandbox exists (step 4).
- **"the sandbox runs security_agent …, the host …":** the code changed since the sandbox was created;
  `sandbox/sandbox.sh create` again.
- **The sandbox is gone** (after a restart of the OpenShell gateway): `sandbox/sandbox.sh create`.
- **The model downloads fail offline:** fill `HF_HOME` once with network access, then set `KB_OFFLINE=1`.
- **`gym:start` stops with `address already in use` on port 11000:** another service holds the port of Gym's head
  server. Pick a free one and pass it to both commands: `hatch run gym:start ++head_server.port=11100`, and the same
  `++head_server.port=11100` after `gym:collect`.
- **Gym's servers keep running after `gym:start` ended:** stop the processes that run from `work/gym/venvs/`, for
  example `pkill -f work/gym/venvs`.
- **`PermissionError` under `~/.cache/huggingface`:** a container created the cache as root. Point `HF_HOME` at a
  directory you own, for example `export HF_HOME=$HOME/hf`, for `build` and the knowledge base alike.
- **Many parse errors or forced answers:** check that the server enforces the thinking budget (`hatch run
  serving:smoke`). Without a cap, the model can think through its whole `max_tokens` and leave no answer.
