# PrimeVul

The PrimeVul files our experiments used, rebuilt with one command from the pinned upstream mirror.

```sh
hatch run primevul:build     # downloads about 64 MB once, writes data/primevul/build/
hatch run primevul:verify    # every rebuilt file's sha256 matches its manifest
```

The build is byte for byte: each rebuilt file has the sha256 of the file the experiments read. It refuses to write a
file whose upstream rows or whole-file hash do not match.

## What is here, and what is not

This repository ships no PrimeVul code. It ships:

- **`upstream.json`:** the Hugging Face mirror [`colin/PrimeVul`](https://huggingface.co/datasets/colin/PrimeVul)
  (config `paired`), pinned at a revision, with the sha256 of its three paired files.
- **`manifests/<file>.manifest.jsonl`:** one per benchmark file. A header line names the source and the file's
  sha256. Each following line places one record: its `id` (PrimeVul's `idx`), `pair_id` and `split`, the upstream
  split and row it comes from, and the sha256 of the function's code.
- **`repository-context/*.commit-repos.json`:** our mapping of fix commits to the repositories that hold them, for
  the commits whose PrimeVul `project_url` was wrong. Round fourteen's repository context uses it.

## The files

| file | pairs | drawn from | used for |
|---|---|---|---|
| `primevul-loop.jsonl` | 100 train, 100 val, 435 holdout | upstream train, validation, test; the holdout is the full paired test split | the self-improvement loops (round seventeen uses the first 60 train and 60 val pairs) and the test-split runs |
| `primevul-dev410.jsonl` | 410 | upstream train, none in the loop's train or val | dev pairs 401–410 are the smoke tests |
| `primevul-dev400.jsonl` | 400 | the first 400 pairs of `dev410` | the 400-pair dev set (rounds fourteen to sixteen, and the model comparison) |
| `primevul-val2.jsonl`, `primevul-val2b.jsonl` | 150, 195 | upstream validation | earlier validation rounds |
| `primevul-smoke13.jsonl` | 10 | pairs from `dev410` | a smoke set |

`build` also writes round fourteen's `primevul-dev410.meta.json` and `primevul-test.meta.json`. They hold PrimeVul's
`project`, `project_url`, `commit_id` and `file_name` per function, plus `repo_url` from `repository-context/`.

Every record has the fields `id`, `code`, `lang`, `gold_is_vulnerable`, `gold_cwe`, `pair_id` and `split`. A pair is
a vulnerable function and its patched twin; a few functions belong to two pairs.

## Rules for using the files

- **Validation and test contents are only aggregated, by scripts.** Nobody reads them, so that design decisions never
  look at the pairs they are judged on.
- **Pinning your own subset:** `hatch run primevul:manifest <your.jsonl>` writes a manifest for any file in this
  record format, and refuses if a record does not match its upstream row exactly.

## License

PrimeVul is MIT-licensed: the original [DLVulDet/PrimeVul](https://github.com/DLVulDet/PrimeVul) and the
`colin/PrimeVul` mirror. Ding et al., *Vulnerability Detection with Code Language Models: How Far Are We?*, ICSE 2025.
