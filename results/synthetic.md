# Results: the repository scan agent

The self-improvement loop turned a weak repository scanner into a more precise one. On the 12 test pairs of the
synthetic benchmark, the improved agent gets 9 pairs right where the starting agent got 4, and raises a false alarm on
1 fixed twin where the starting agent raised 7. Over the 46 test pairs of our three benchmarks it gets 26 right instead
of 19. The optimizer built the improvement itself, within fixed gates and without a person editing the agent: a long
prompt, a step that withdraws findings on safe code and a search tool, about 300 lines of prompt and Python in all.

The public benchmark is [`data/synthetic-components/`](../data/synthetic-components/); the runbook to rerun it is
[`docs/synthetic.md`](../docs/synthetic.md).

## The benchmarks

Each pair is two copies of a repository of custom Haystack components: one with a planted vulnerability, and its fixed
twin, identical except that the vulnerability is fixed. The agent scans each copy as a whole repository and never knows
which of the two it is looking at.

- **Synthetic** ([`data/synthetic-components/`](../data/synthetic-components/)): 50 pairs of small generated
  repositories, 20 vulnerability types. Public.
- **Core integrations:** vulnerabilities planted into packages of
  [haystack-core-integrations](https://github.com/deepset-ai/haystack-core-integrations). Not published.
- **Customer:** vulnerabilities planted into anonymized repositories of customer components, the largest repositories
  of the three. Confidential.

Each benchmark is split by repository, about 50/25/25, so that copies of one repository stay in one set. The synthetic
split is [`split.json`](../src/security_agent/synthetic/config/split.json): 25 training, 13 validation and 12 test
pairs. Over the three benchmarks, the loop trained on a fixed 72 training pairs, 24 per benchmark; there are 47
validation pairs and 46 test pairs (12 synthetic, 22 core integrations, 12 customer).

## The agents

- **seed** ([`agents/synthetic/seed/`](../agents/synthetic/seed/)): the starting point, a Haystack Agent with the
  repository's file list, a size-capped `read_file`, Monty's sandboxed `run_python`, a short generic prompt and low
  limits (15 steps, a 1,024-token thinking budget).
- **looped** ([`agents/synthetic/looped/`](../agents/synthetic/looped/)): what the loop made of the seed.
  - A long system prompt that names vulnerability classes in Haystack components and, for each, the safe form that
    must not be reported.
  - A `search` tool across the whole repository.
  - A `verifier` step after the agent: it shows the model each finding with the code around it, and retracts the
    finding when the model is confident that a control makes the code safe.
  - Higher limits: 30 steps, a 4,096-token thinking budget.
  - A `hunter` step that greps for dangerous patterns and leaves notes for the agent. Nothing connects it ahead of the
    agent, so the notes never reach it: in every scan we measured, the agent started without them.

Both ran on Nemotron 3.5 Super VL (vLLM, [`serving/nemotron-3.5-super-vl/`](../serving/nemotron-3.5-super-vl/)), with
temperature 0 on every call that has a thinking budget.

## Numbers

A pair is **right** when the agent reports a finding within 2 lines of the planted lines in the vulnerable copy, and
none at the corresponding lines of its fixed twin, whatever the vulnerability type. This is the benchmark's
`paired_localization_accuracy`, and the number on the talk's slide.

**Test pairs, the numbers on the slide:**

| Test set | Pairs right: seed | looped | Fixed twins flagged: seed | looped |
|---|---|---|---|---|
| Synthetic (12 pairs) | 4 (33.3%) | **9 (75.0%)** | 7 (58.3%) | **1 (8.3%)** |
| Core integrations (22 pairs) | 12 (54.5%) | 11 (50.0%) | 4 (18.2%) | **2 (9.1%)** |
| Customer (12 pairs) | 3 (25.0%) | **6 (50.0%)** | 2 (16.7%) | 2 (16.7%) |
| **All three (46 pairs)** | 19 (41.3%) | **26 (56.5%)** | 13 (28.3%) | **5 (10.9%)** |

**Per benchmark:**

*Synthetic*

| | seed | looped |
|---|---|---|
| **Test pairs right** (of 12) | 4 (33.3%) | **9 (75.0%)** |
| **Validation pairs right** (of 13) | 8 (61.5%) | **10 (76.9%)** |
| Training pairs right (of 24) | 9 (37.5%) | 19 (79.2%) |
| **Test: fixed twins flagged at the corresponding lines** | 7 of 12 | **1 of 12** |
| Test: vulnerable copies flagged at the planted lines | 11 of 12 | 10 of 12 |
| Test: precision (vulnerable copies among the flagged copies) | 61.1% | **90.9%** |
| Validation: fixed twins flagged | 5 of 13 | 2 of 13 |
| Test: tokens per repository scan | 18k | 25k |

*Core integrations*

| | seed | looped |
|---|---|---|
| **Test pairs right** (of 22) | **12 (54.5%)** | 11 (50.0%) |
| **Validation pairs right** (of 21) | 7 (33.3%) | **8 (38.1%)** |
| Training pairs right (of 24) | 10 (41.7%) | 13 (54.2%) |
| **Test: fixed twins flagged at the corresponding lines** | 4 of 22 | **2 of 22** |
| Test: vulnerable copies flagged at the planted lines | 16 of 22 | 13 of 22 |
| Test: precision (vulnerable copies among the flagged copies) | 80.0% | **86.7%** |
| Validation: fixed twins flagged | 7 of 21 | 4 of 21 |
| Test: tokens per repository scan | 132k | 214k |

*Customer*

| | seed | looped |
|---|---|---|
| **Test pairs right** (of 12) | 3 (25.0%) | **6 (50.0%)** |
| **Validation pairs right** (of 13) | **8 (61.5%)** | 7 (53.8%) |
| Training pairs right (of 24) | 10 (41.7%) | 19 (79.2%) |
| **Test: fixed twins flagged at the corresponding lines** | 2 of 12 | 2 of 12 |
| Test: vulnerable copies flagged at the planted lines | 5 of 12 | 8 of 12 |
| Test: precision (vulnerable copies among the flagged copies) | 71.4% | **80.0%** |
| Validation: fixed twins flagged | 0 of 13 | 1 of 13 |
| Test: tokens per repository scan | 172k | 390k |

Over all three benchmarks, the looped agent's precision on the test pairs rises from 71.1% to 86.1% and its recall stays
about the same (67.4% against 69.6%). It uses about 1.9 times the seed's tokens per scan (203k against 109k), and about
3 times its estimated GPU time.

## How the loop ran

The optimizer, an agent on the same model, wrote Python tools and pipeline steps for the scanner, changed its prompts
and raised its limits. Each candidate was scanned on the 72 training pairs, and the results, with failure reports and
the scanning agent's reasoning, came back to it. Every candidate had to pass fixed gates on the training pairs: at most
6 estimated GPU-minutes and 10 findings per repository, no copied training answers, and the contract test of its code.

1. **Selection on validation.** A candidate was accepted only with at least 3 more validation pairs right than the
   best so far; the optimizer learned only "accepted" or "not accepted". After three candidates in a row without that,
   this stage ended with none: all three gained strongly on the training pairs (up to 64%, from 40%), none on
   validation.
2. **Hill-climbing on the training pairs,** from the first stage's best on training: a candidate became the next
   starting point when it got more training pairs right. Every eligible candidate was also scanned on the validation
   pairs, which the optimizer never saw. Four candidates until the deadline.

The looped agent is the second stage's candidate with the most validation pairs right. The test pairs were looked at
once, at the end, with it.


To rerun the synthetic test numbers: steps 1 to 4 of the [runbook](../docs/synthetic.md). The other two benchmarks
can't be rerun from this repository.
