# Evolve within bounds

A self-improving security agent built with [Haystack](https://github.com/deepset-ai/haystack) that runs entirely on
one NVIDIA DGX Spark. A self-improvement loop rewrites the agent's prompt and writes, tests and installs new analysis
tools for it. The bounds:

- **The agent's sandbox:** the agent runs in an OpenShell sandbox, created through NemoClaw.
- **The tools' sandbox:** code the model writes runs in the Monty sandbox.
- **Evaluation rules:** every change must pass fixed gates on training pairs and a held-out validation check before it
  is kept.
- **Local models only:** Qwen3.8 Flash-Next and NVIDIA Nemotron 3.5, served with vLLM or NVIDIA NIM.

The benchmark is [PrimeVul](https://github.com/DLVulDet/PrimeVul) paired vulnerability detection: each pair is a
vulnerable function and its patched version.

> **Status:** work in progress. The code, agents, serving recipes and results are being moved in from internal
> repositories.

## Layout

| Folder | What it holds |
|---|---|
| [`docs/`](docs/) | architecture, DGX Spark setup, the self-improvement loop, how to reproduce each result, the pre-registered experiments |
| [`src/security_agent/`](src/security_agent/) | the Python package: agents, tools, knowledge base, the optimization loop, benchmarks, NeMo Gym environment |
| [`agents/`](agents/) | agent YAML files: the seed agent, the controls, and the agents the loop produced |
| [`serving/`](serving/) | one folder per model: pinned revision and image, serve script, measured speed |
| [`sandbox/`](sandbox/) | the security-triage agent for NemoClaw/OpenShell, its egress policy and inference wiring |
| [`gym/`](gym/) | the NeMo Gym environment configuration |
| [`data/`](data/) | PrimeVul pair-id manifests and the synthetic custom-component dataset |
| [`scripts/`](scripts/) | setup, data preparation, benchmarks, evaluation, one entry point per experiment |
| [`results/`](results/) | the numbers we report, with the command that produced each |
| [`tests/`](tests/) | unit tests that run without a GPU |

## Requirements

- An NVIDIA DGX Spark (GB10, 128 GB unified memory) with Docker and the NVIDIA Container Toolkit.
- [Hatch](https://hatch.pypa.io/latest/install/) for the Python environments.
- A Hugging Face token for the model downloads, and an NGC API key for NIM containers.

## Quick start

- **Set up the agent:** see `docs/setup-dgx-spark.md` (coming).
- **Reproduce the results:** see `docs/reproducing-results.md` (coming).

## Development

```sh
hatch run fmt          # format and lint
hatch run test:unit    # unit tests, no GPU needed
hatch run test:types   # type checks
```

## License

Apache-2.0, see [LICENSE](LICENSE). Third-party software, models and datasets keep their own licenses, see
[NOTICE](NOTICE).
