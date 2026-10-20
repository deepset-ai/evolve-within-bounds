# Evolve within bounds

A self-improving security agent built with [Haystack](https://github.com/deepset-ai/haystack) that runs entirely on
one NVIDIA DGX Spark. A self-improvement loop rewrites the agent's prompt or writes new analysis tools for it, and
keeps a change only if it passes fixed checks. The bounds:

- **The agent's sandbox:** the agent is deployed in an OpenShell sandbox, created through NemoClaw.
- **The tools' sandbox:** Python the agent runs itself goes through Monty.
- **Evaluation rules:** every change must pass fixed gates on training pairs. Held-out validation pairs decide which
  improved agent we report.
- **Local models only:** NVIDIA Nemotron 3.5 Lightning and Qwen3.8 Flash-Next, served with vLLM or llama.cpp in our
  runs. [`serving/`](serving/) also sets up NVIDIA NIM.

There are two benchmarks:

- **[PrimeVul](https://github.com/DLVulDet/PrimeVul), paired:** each pair is a vulnerable C/C++ function and its
  patched version.
- **Synthetic custom components:** 50 pairs of small Haystack component repositories. One repository of each pair has
  a planted vulnerability and the other is its fixed twin. The agent scans each one as a whole repository.

> **Status:** work in progress. The code, agents and serving recipes to rerun them are being moved
> in from internal repositories.

## Background

- **NVIDIA GTC session:** [Evolve Within Bounds: Secure, Self-Improving Agents for On-Prem AI](https://www.nvidia.com/en-eu/gtc/session-catalog/sessions/gtceu26-sb61130/).
- **Blog post:** [Self-Improving AI Systems: A Log-Analysis Agent on NVIDIA DGX Spark](https://haystack.deepset.ai/blog/self-improving-agent-dgx-spark),
  on the Haystack blog. The same approach applied to another use case: a Haystack agent analyzes recorded traces of a
  citizen-services AI assistant and improves it, with local models on a DGX Spark.

## Layout

| Folder | What it holds |
|---|---|
| [`docs/`](docs/) | DGX Spark setup, one runbook per benchmark, and the architecture |
| [`src/security_agent/`](src/security_agent/) | the Python package: the self-improvement loop the benchmarks share (`optimize/`), the repository scan agent and its benchmark task (`synthetic/`), the PrimeVul triage agent's runner and scoring (`primevul/`) and its knowledge base (`knowledge_base/`), the model servers' smoke check, the PrimeVul data |
| [`agents/`](agents/) | the agents behind the results: the seed and the improved agents for each benchmark |
| [`serving/`](serving/) | one folder per model: pinned revision and image, serve script, smoke check; and Qdrant, for PrimeVul's knowledge base |
| [`sandbox/`](sandbox/) | the OpenShell sandbox, created through NemoClaw, that the synthetic benchmark's scans run in: the image, its policy, the inference route |
| [`gym/`](gym/) | the NeMo Gym environments for both benchmarks: resources servers that score rollouts with each benchmark's own scoring, and agent servers that run our agents (PrimeVul's agent files through Gym's Haystack harness, the synthetic benchmark's scanner as a black-box harness) |
| [`data/`](data/) | PrimeVul pair-id manifests and the synthetic custom-component dataset |
| [`scripts/`](scripts/) | setup, data preparation, evaluation, one entry point per experiment |
| [`results/`](results/) | what came out of our runs, and how each number was produced |
| [`demo/`](demo/) | the talk's live demo: one iteration of the self-improvement loop on the synthetic benchmark, approved by a person and deployed into the sandbox, in about 3 to 5 minutes |
| [`tests/`](tests/) | unit tests that run without a GPU |
| [`cve-triage/`](cve-triage/) | a separate Haystack agent that triages the security advisories for a Python repository's dependencies. It calls cloud APIs (OpenAI, You.com, Fastino), so the bounds above don't apply to it |

## Requirements

- An NVIDIA DGX Spark (GB10, 128 GB unified memory) with Docker and the NVIDIA Container Toolkit.
- [Hatch](https://hatch.pypa.io/latest/install/) for the Python environments, and Node.js 22.19 or newer for NemoClaw.
- A Hugging Face token for the model downloads, and an NGC API key for NIM containers.

## Run it yourself

- **Data:** both benchmarks already build with one command each, see [`data/`](data/).
- **Synthetic custom components:** see [`docs/synthetic.md`](docs/synthetic.md). Serve Flash-Next with vLLM, create
  the sandbox, scan with both agents inside it, run the loop, then approve an improvement and deploy it there; and roll
  the agents out with NeMo Gym.
- **The demo:** see [`demo/README.md`](demo/README.md).
- **PrimeVul:** see [`docs/primevul.md`](docs/primevul.md). Build the benchmark file and the knowledge base, serve
  Flash-Next with vLLM, measure both agents on the test pairs, run the prompt loop, and roll the agents out with NeMo
  Gym.

## Development

```sh
hatch run fmt          # format and lint
hatch run test:unit    # unit tests, no GPU needed
hatch run test:types   # type checks
```

## License

Apache-2.0, see [LICENSE](LICENSE). Third-party software, models and datasets keep their own licenses, see
[NOTICE](NOTICE).
