# Scripts

Planned:

- `setup/`: DGX Spark bootstrap (Docker, NVIDIA Container Toolkit, Hatch, Qdrant, NGC login).
- `data/`: fetch PrimeVul, build the splits from the manifests, build the knowledge base.
- `bench/`: the speed benchmark, the server probes, and a fetcher for the third-party benchmark harness at a pinned
  commit.
- `eval/`: scoring (paired accuracy, d′, tetrachoric ρ, sign-flip permutation test) and comparisons between runs.
- `run/`: one entry point per experiment.
