# Benchmark design

## Corpus

44 synthetic Haystack custom-component repositories, authored from scratch and vendored in
full under `corpus/`. Each is a realistic small package: an Apache-2.0 licence, a
`pyproject.toml`, CI configuration, one or more components, and a test suite.

Themes are **technical, not vertical** — `synth-07-service-proxy`,
`synth-21-markdown-table-renderer` — describing what a component does rather than what
industry it serves. Three package layouts are used (26 `src/custom_components/…`, 15
`src/haystack_integrations/components/…`, 3 nested) so an agent cannot key on one path
shape. `data/themes.json` records one card per repository: its domain statement, the
recipes it hosts, and the near-miss distractors it carries.

### Pinning without a remote

There is no repository to clone and no commit to pin. Each tree is pinned by a content
digest recorded in `data/repositories.json`:

```
h = sha256()
for relpath in sorted(walk(tree)):        # POSIX strings, byte-sorted, excluded names skipped
    if symlink: h.update(b"l\0" + relpath + b"\0" + target + b"\0")
    else:       h.update(b"f" + (b"x" if executable else b"-") + b"\0"
                         + relpath + b"\0" + str(len(data)) + b"\0" + data)
```

Every element is load-bearing. The type tag separates a symlink from a file containing its
target as content; the executable bit makes a `chmod` visible; the length prefix removes
ambiguity across the path/content boundary. Raw bytes are hashed, never decoded text —
hence the `-text` rules in `.gitattributes`, without which a Windows checkout would rewrite
line endings and invalidate every digest.

Validation additionally checks that every corpus file is tracked by git and that none is
ignored. An untracked file would be exported on the author's machine and absent everywhere
else — the one drift a content digest cannot see.

### Boilerplate conformance

44 copies of the same scaffolding would bury the security-relevant code in review noise.
`tools/canon/` holds the canonical boilerplate with substitution tokens, and
`python3 tools/scaffold.py check` asserts every tree matches it byte-for-byte after
substitution. A reviewer reads the canon once and 44 green checks, then spends real
attention on `src/` and `tests/`.

## Mutations

Whole-file variants under `mutations/<pair_id>/mutant/files/` are the **source of truth**.
Unified diffs, line spans, patch digests and delta fingerprints are all derived by
`tools/build_corpus.py`; no line number is ever typed by hand. Validation re-derives the
spans and asserts they *equal* the declared values, which is strictly stronger than
checking that a declared span overlaps a hunk.

The derived patch is committed to `patches/` so a pull request still reviews as a delta,
and validation proves patch and files agree. Overlays express modification and addition,
not deletion; no recipe currently needs deletion.

### Composition

50 planted pairs across all 27 vulnerability families: 5 families with 3 pairs, 13 with 2,
9 with 1. The five families at 3 pairs were chosen because each admits three structurally
different mutations — a single-line guard removal, a multi-line refactor, and a multi-file
taint flow — so the extra pairs measure within-family variance instead of repeating an
edit.

A **`delta_fingerprint`** (sha256 of the normalized diff body) is asserted globally unique
across all pairs. This is a mechanical guard, and it earns its place: it caught two
independently authored `R24` mutations that had converged on the identical edit.

Ten pairs span two files. `targets[]` records each file with a `role` of `source`,
`propagation` or `sink`.

## Placebo controls

Twelve pairs carry a third member: the same baseline with a *benign* change applied to the
**same lines** as the mutation — a rename, a reordering, an added log record, a tightened
guard, an extracted helper. Twelve different families and five edit kinds, so the slice is
not confounded with one recipe or one style.

A placebo is a third member rather than a standalone pair because a standalone control
cannot express "the same lines" at all, costs two instances instead of one, and has
`mutant_detected` permanently false — silently depressing the primary metric unless a
filter is threaded through every computation. As a third member the planted denominator
stays at 50 and every existing metric keeps its exact value.

Placebo matching is necessarily CWE-agnostic: a benign edit has no expected weakness class,
so any finding at the changed span is a false alarm.

## Metrics

For planted pair \(i\), with \(V_i=1\) when a prediction matches the mutant sink and
\(B_i=1\) when one matches the mapped baseline sink:

\[
\text{strict paired accuracy} = \frac{1}{N}\sum_{i=1}^{N}\mathbb{1}[V_i=1 \land B_i=0]
\]

A match requires normalized path equality, line-span overlap within the tolerance
(default 2), and an exact or explicitly compatible CWE.

`paired_localization_accuracy` repeats the computation with the CWE condition removed.
`placebo.change_induced_false_alarm_rate` is the placebo analogue of the pairing rule:
alarm on the benign member *and not* on the baseline, which isolates "the edit made the
scanner cry wolf" from "the scanner always alarms here". Every placebo key contains
*rate*, never *accuracy*, so the direction is unambiguous beside the higher-is-better
metrics.

Multi-file pairs are matched at the sink on both members. Symmetry preserves the meaning
of the pairing rule, and sink-only keeps single-file numbers identical to a single-target
corpus. `mutant_detected_any_target` appears in per-pair rows so "saw the source, missed
the sink" is observable without another headline number.

## Release gates

Because the corpus is authored rather than collected, checks that a proprietary corpus has
to forgo all run here, unconditionally, with no network and no cache:

- every baseline, mutant **and** placebo test suite passes. If a mutation broke the
  repository's own tests, `pytest` would be a free oracle for the planted vulnerability;
  45 such tests were removed during authoring, leaving each vulnerable path deliberately
  under-tested — which is where real bugs live anyway;
- every corpus tree matches its digest, is fully tracked, contains no `.git`, no CRLF, no
  case-colliding paths and no escaping symlinks;
- every patch touches exactly its declared target set, with no renames and no
  new-or-deleted-file headers, and its per-file hunks justify that file's spans;
- every mutant target parses as Python after the patch is applied;
- `delta_fingerprint` uniqueness, the recipe cap, and full family coverage;
- placebo diffs fall inside the planted size range, so controls cannot be identified by
  diff size;
- no added line carries a non-canary credential literal, a commit-shaped hex run, or a
  non-reserved host.

Materialization normalizes every file's mtime to a fixed epoch so timestamps cannot
distinguish members.
