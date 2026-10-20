# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The self-improvement loop, shared by the benchmarks.

- `loop`: the experiment: pre-registration, measurements, gates, the decision;
- `task`: what a benchmark provides to the loop (`security_agent.synthetic.task` for the synthetic benchmark);
- `proposer`: the optimizer, a Haystack Agent that edits a draft candidate;
- `workspace`: the optimizer's tools on the draft;
- `measurement`, `leakage`, `splits`, `candidate`: measurements, refusing candidates that copy training answers, which
  pairs are for training, and candidate identity and diffs.

The loop only reads the training pairs. Validation and test are for the benchmark's own evaluation afterwards.
"""
