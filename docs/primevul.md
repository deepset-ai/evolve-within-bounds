# Runbook: PrimeVul

This runbook reruns our PrimeVul results on one DGX Spark: build the benchmark file and the knowledge base, serve the
model, and measure the two agents on the test pairs.

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

- An NVIDIA DGX Spark with Docker and [Hatch](https://hatch.pypa.io/latest/install/).
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
`http://127.0.0.1:8000/v1` as `qwen3.8-flash-next`.

## 4. Measure both agents

Try the mechanics on one training pair first:

```bash
hatch run primevul:run --agent agents/primevul/seed --split train --pairs 1
```

Then the first 100 test pairs:

```bash
hatch run primevul:run --agent agents/primevul/seed   --split test --pairs 100
hatch run primevul:run --agent agents/primevul/looped --split test --pairs 100
```

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
wrong.

## Troubleshooting

- **Every briefing says "Cannot reach Qdrant" or "No knowledge base":** the tool reports instead of failing, so the run
  goes on without it. Start Qdrant and build the knowledge base (step 2); `kb query` checks both.
- **The model downloads fail offline:** fill `HF_HOME` once with network access, then set `KB_OFFLINE=1`.
- **`PermissionError` under `~/.cache/huggingface`:** a container created the cache as root. Point `HF_HOME` at a
  directory you own, for example `export HF_HOME=$HOME/hf`, for `build` and the knowledge base alike.
- **Many parse errors or forced answers:** check that the server enforces the thinking budget (`hatch run
  serving:smoke`). Without a cap, the model can think through its whole `max_tokens` and leave no answer.
