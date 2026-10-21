# Data

## Synthetic custom components (`synthetic-components/`)

A paired, whole-repository benchmark for agents that find security vulnerabilities in Haystack custom components:

- 44 synthetic component repositories;
- 50 mutation pairs: each is a clean baseline and a variant with one planted vulnerability, covering 27 vulnerability
  families (10 of the pairs span two files);
- 12 placebo controls: a benign edit to the same lines a mutation changes;
- 112 blinded scan instances.

Everything is synthetic: no customer code, no credentials, and no network access is needed. The benchmark's own
[README](synthetic-components/README.md) describes the prediction format and the metrics (strict paired accuracy,
paired localization accuracy, the placebo false-alarm rate), and
[docs/benchmark.md](synthetic-components/docs/benchmark.md) the corpus design and ground truth.

**Provenance.** Copied byte for byte from deepset-ai/haystack-component-vulnerability-benchmark at commit 3e2f443
(2026-09-22), authored by Bogdan Kostic. Four things were left out:

- `tools/`: the scripts that authored and regenerated the corpus. Replicating results never runs them. Without them,
  the boilerplate-conformance test skips by design.
- The benchmark's CI workflow, which this repository's CI replaces.
- The generated validation report.
- A duplicate of the Apache-2.0 license.

The only edits are in its `pyproject.toml` (placeholder URLs removed, the corpus excluded from linting) and one link in
its README.

**Run it** from the repository root:

```sh
hatch run components:inventory                      # what the benchmark contains
hatch run components:validate                       # digests, patches, spans, identifiers
hatch run components:test                           # the benchmark's own test suite
hatch run components:materialize --output materialized
hatch run components:score predictions.jsonl --output reports/score.json
```

`materialize` writes the blinded instances and `scan_manifest.jsonl`. It keeps the answer key separately, outside the
scan output.

**Keep the answer key away from the agent.** Everything under `synthetic-components/` is the answer key:
`data/pairs.jsonl` maps instance ids to labels, and `mutations/` and `patches/` show the planted changes. An agent
under evaluation may only ever see one materialized instance. The sandbox image therefore installs the agent package
(`src/`) and never `data/`.

**Never edit the corpus by hand.** Each repository tree is pinned by a content digest of its raw bytes
(`data/repositories.json`), and `.gitattributes` keeps git from rewriting line endings. Linters and pre-commit hooks
are configured to leave `corpus/`, `mutations/` and `patches/` alone. `hatch run components:validate` checks all of
this.

## PrimeVul (`primevul/`)

The PrimeVul files the experiments used: the self-improvement loop's train, validation and holdout pairs, the 400-pair
dev set, and smaller validation and smoke sets. `hatch run primevul:build` rebuilds them byte for byte from the pinned
Hugging Face mirror. This repository holds only manifests (ids, splits, upstream rows and hashes), and no PrimeVul
code except the 24 functions of the GUI's pairs tab (`gui/shipped/pairs.json`).
See [primevul/README.md](primevul/README.md).

## Knowledge base

The PrimeVul agent's knowledge base, the CWE reference and the CERT C rules, is built by `scripts/data/` from the public
sources, not shipped.
