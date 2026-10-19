# NeMo Gym

Both benchmarks' agents as [NeMo Gym](https://github.com/NVIDIA-NeMo/Gym) environments (nemo-gym 0.7.0). The runbook
steps are [`docs/primevul.md`](../docs/primevul.md), step 6, and [`docs/synthetic.md`](../docs/synthetic.md), step 7.

| Folder | What it holds |
|---|---|
| [`resources_servers/primevul/`](resources_servers/primevul/) | PrimeVul's resources server: scores each rollout with this repository's verdict parser, and the run's pairs with its pair scoring (`security_agent.primevul.gym`); the Gym config ([`configs/primevul.yaml`](resources_servers/primevul/configs/primevul.yaml)) and a made-up example dataset |
| [`responses_api_agents/primevul_agent/`](responses_api_agents/primevul_agent/) | PrimeVul's agent server: Gym's Haystack harness, given one of the agent files in [`agents/primevul/`](../agents/primevul/). It swaps the agent's chat generator for Gym's and keeps everything else |
| [`resources_servers/synthetic/`](resources_servers/synthetic/) | the synthetic benchmark's resources server: scores each scanned repository, and the run's pairs, with the benchmark's own scorer and answer key (`security_agent.synthetic.gym`); the Gym config ([`configs/synthetic.yaml`](resources_servers/synthetic/configs/synthetic.yaml)) and an example dataset of two training pairs |
| [`responses_api_agents/synthetic_agent/`](responses_api_agents/synthetic_agent/) | the synthetic benchmark's agent server: runs our scanner, unchanged, with one of the agents in [`agents/synthetic/`](../agents/synthetic/) on the repository a row names, and sends its model calls through Gym's model server |

**Two ways into Gym.** A PrimeVul agent is one Haystack `Agent`, which is what Gym's Haystack harness runs. The
synthetic benchmark's scanner is a pipeline around an `Agent`, with its own tools, the steps the optimizer wrote and a
normalizer, so its agent server runs it the way Gym runs other black-box harnesses: it gives the scanner the address of
Gym's model server for the rollout, and builds the response from the scan's conversation. The scan's findings travel
with the response (`metadata.findings`); the answer key never leaves the resources server.

Each config starts six servers: the resources server, Gym's vLLM model server (pointed at the Flash-Next server from
[`serving/`](../serving/)), one agent server per agent, and an environment server in front of each agent. For PrimeVul
the model server adds the thinking budget the agents ran with; on the synthetic benchmark, each request brings its
agent's own.

```bash
# PrimeVul
hatch run primevul:gym export --split train --pairs 2   # rows for `collect`, in work/gym/primevul/
hatch run gym:start                                     # the servers; stop with Ctrl-C
hatch run gym:collect --agent primevul_seed --input work/gym/primevul/train-2.jsonl --output runs/primevul/gym/seed.jsonl

# The synthetic benchmark
hatch run synthetic:gym export --split train --pairs 2  # rows for `collect-synthetic`, in work/gym/synthetic/
hatch run gym:start-synthetic
hatch run gym:collect-synthetic --agent synthetic_seed --input work/gym/synthetic/train-2.jsonl --output runs/synthetic/gym/seed.jsonl

hatch run gym:test                                      # the servers' own tests
```

`hatch run gym:...` runs Gym through uv, which provides the Python 3.13.14 or newer that nemo-gym needs. Gym builds an
environment for each server, in `work/gym/venvs/`; all of ours install this repository's package.
[`pyproject.toml`](pyproject.toml) here is only a marker that makes Gym install their `requirements.txt` as written.
