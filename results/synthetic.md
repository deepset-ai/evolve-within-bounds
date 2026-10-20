# Results: the synthetic custom-component benchmark

The self-improvement loop turned a weak repository scanner into a better and more precise one. On held-out pairs the
improved agent gets more pairs right, on validation and on test, and raises a false alarm on 1 safe twin where the
starting agent raised 5. The optimizer built the improvement itself: three pipeline steps, three tools and a new
prompt, about 1,500 lines of Python, within fixed gates and without a person editing the agent.

The benchmark is [`data/synthetic-components/`](../data/synthetic-components/); the runbook to rerun it is
[`docs/synthetic.md`](../docs/synthetic.md).

## The agents

- **seed** ([`agents/synthetic/seed/`](../agents/synthetic/seed/)): the starting point, a Haystack Agent with the
  repository's file list, a size-capped `read_file`, Monty's sandboxed `run_python`, a short generic prompt and low
  limits.
- **looped** ([`agents/synthetic/looped/`](../agents/synthetic/looped/)): what the loop made of the seed.
  - Pipeline steps: `guards` (rule-based detectors for a control the project applies everywhere but at one
    statement), `hunter` (one model pass over every file, before the agent starts) and `verifier` (compares each
    finding with how the same kind of statement is written elsewhere in the project, and retracts it if they match).
  - Tools for the agent: `search` across the whole repository, `outline` of one file, and `rare`, which lists the
    statements that differ from the rest of their family.
  - A rewritten system prompt, and higher limits.

Both ran on Qwen3.8 Flash-Next (vLLM with the UltraFast recipe, [`serving/qwen3.8-flash-next/`](../serving/qwen3.8-flash-next/))
at temperature 0.

## Numbers

A pair is **right** when the agent reports a finding within 2 lines of the planted lines in the vulnerable repository
and none at the corresponding lines of its safe twin. This is the benchmark's `paired_localization_accuracy`, and the
number on the talk's slide.

| | seed | looped |
|---|---|---|
| **Test pairs right** (of 12) | 7 (58.3%) | **8 (66.7%)** |
| **Validation pairs right** (of 13) | 7 (53.8%) | **9 (69.2%)** |
| Training pairs right (of 12) | 7.5 (62.5%, mean of 2 runs) | 8 (66.7%) |
| **Test: safe twins flagged at the corresponding lines** | 5 of 12 | **1 of 12** |
| Test: precision (planted defects among the flagged lines) | 70.6% | **90.0%** |
| Validation: safe twins flagged | 6 of 13 | 4 of 13 |
| Test: findings | 33 | 29 |
| Test: tokens per repository scan | 45k | 81k |

Test and validation include the placebo repositories of some pairs, 28 scans each. Every scan completed.

## What the loop changed

- **Far fewer false alarms.** The seed flags every planted defect, but the safe twin along with it in 5 of 12 test
  pairs. The looped agent's verifier asks whether a flagged statement really differs from the project's other
  statements of its kind, which is exactly what tells a planted defect from its fixed twin: 1 safe twin flagged, and
  90% of the flagged lines are planted defects.
- **More pairs right on both held-out sets**: +1 on test, +2 on validation, with fewer findings in total.
- **Built by the optimizer, inside the bounds.** Every candidate had to pass fixed gates on the training pairs: at
  most 6 estimated GPU-minutes and 10 findings per repository, no copied training answers, and the contract test of
  its code. A person picked the looped agent on the validation pairs, and approves it before it is deployed.
- **At a moderate cost:** 1.8 times the seed's tokens per scan, with about the same number of output tokens.

## Caveats

- One run per agent, and small sets: one pair is 8 points. Read the pair counts as a direction.
- The objective counts where a finding is, not its CWE. The looped agent's `guards` step labels its findings with a
  generic CWE (CWE-1188), so with the CWE required as well it gets 4 test pairs right, against the seed's 9.
- The loop trained on these 12 training pairs together with 24 pairs from two internal benchmarks that we cannot
  publish. The validation and test pairs never entered it.

To rerun the test numbers: steps 1 to 4 of the [runbook](../docs/synthetic.md).
