# Haystack Component Vulnerability Benchmark

A paired, whole-repository benchmark for agents that find security vulnerabilities in
Haystack custom components containing:

- 44 synthetic component repositories, vendored in full and pinned by content digest;
- 50 one-delta mutation pairs covering **all 27** vulnerability recipe families, with no
  family exceeding 3 pairs;
- 10 multi-file mutations where the taint flows from a source module to a sink module;
- 12 placebo controls — a *benign* edit to the same lines as the mutation;
- 112 blinded scan instances.

Everything is synthetic and Apache-2.0 licensed. There is no customer code, no network
access, no credentials, and no repository to clone: `pip install` and run.

## Quick start

Requirements: Python 3.11+ and `git` (used only to apply mutation patches locally).

```bash
pip install -e ".[test]"

hvbench inventory
hvbench validate
hvbench materialize --output materialized
```

`materialized/scan_manifest.jsonl` is the scanner input. Each row carries only an opaque
`instance_id` and an absolute `path`. The mapping back to pair and member is written to
`reports/answer_key.json`, **outside** the scan output.

Filesystem-isolate the agent to a single path from the manifest. Note that
`data/pairs.jsonl` maps instance ids to labels, so this repository is itself the answer
key — the agent must not be able to read it.

## Prediction format

One JSONL object per instance, including instances with no findings:

```json
{"instance_id":"instance-0123456789abcdefabcd","findings":[{"path":"src/custom_components/pkg/component.py","line_start":42,"line_end":44,"cwe":"CWE-89","title":"Unparameterized SQL"}]}
```

All 112 instances must appear, so a crashed scan cannot be read as a clean result.

```bash
hvbench score predictions.jsonl --output reports/score.json
```

## Metrics

**`strict_paired_accuracy`** (primary) — a pair counts only when the planted finding is
localized in the mutant *and* no compatible finding is reported at the mapped location in
the baseline. Flagging both scores zero.

**`paired_localization_accuracy`** — the same pairing rule with CWE ignored. It measures
whether the agent found the right code rather than whether it named the right weakness
class. The gap between the two is the taxonomy penalty.

**`placebo.change_induced_false_alarm_rate`** — how often a *benign* edit to the mutated
lines triggers a finding. This is the metric the paired design alone cannot provide: an
agent that reports every changed span scores a perfect 1.0 strict paired accuracy and is
indistinguishable from a real detector until the placebo controls separate them.
`discrimination_index` (`strict − change_induced`) collapses that into one number; it is a
difference of rates over different denominators, so it is informative, never an accuracy.

Also reported: mutant recall, mapped-location false-alarm rate, per-recipe and per-CWE
slices, and per-pair rows including `mutant_detected_any_target` for multi-file pairs.

Multi-file pairs are scored at the **sink**, symmetrically on both members, so single-file
numbers are unaffected and reporting a taint source without its sink does not score.

## Limitations

- The corpus is ~5,000 lines of synthetic Python across 44 small repositories. Real
  custom-component estates are considerably larger, and needle-in-haystack difficulty
  scales with haystack size, so **scores here are not comparable to scores on a
  proprietary corpus.** Difficulty comes from near-miss distractors rather than volume.
- Every mutant introduces exactly one vulnerability. Real regressions arrive in batches.
- CWE matching is location-aware but cannot establish semantic equivalence across every
  scanner taxonomy; `paired_localization_accuracy` exists to quantify that.

See [docs/benchmark.md](docs/benchmark.md) for corpus design, ground-truth semantics and
metric details.
