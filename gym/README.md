# NeMo Gym

The PrimeVul agents as a [NeMo Gym](https://github.com/NVIDIA-NeMo/Gym) environment (nemo-gym 0.7.0). The runbook step
is [`docs/primevul.md`](../docs/primevul.md), step 6.

| Folder | What it holds |
|---|---|
| [`resources_servers/primevul/`](resources_servers/primevul/) | the resources server: scores each rollout with this repository's verdict parser, and the run's pairs with its pair scoring (`security_agent.primevul.gym`); the Gym config ([`configs/primevul.yaml`](resources_servers/primevul/configs/primevul.yaml)) and a made-up example dataset |
| [`responses_api_agents/primevul_agent/`](responses_api_agents/primevul_agent/) | the agent server: Gym's Haystack harness, given one of the agent files in [`agents/primevul/`](../agents/primevul/). It swaps the agent's chat generator for Gym's and keeps everything else |

The config starts six servers: the resources server, Gym's vLLM model server (pointed at the Flash-Next server from
[`serving/`](../serving/), with the thinking budget the agents ran with), one agent server per agent, and an environment
server in front of each agent.

```bash
hatch run primevul:gym export --split train --pairs 2   # rows for `collect`, in work/gym/primevul/
hatch run gym:start                                     # the servers; stop with Ctrl-C
hatch run gym:collect --agent primevul_seed --input work/gym/primevul/train-2.jsonl --output runs/primevul/gym/seed.jsonl
hatch run gym:test                                      # the servers' own tests
```

`hatch run gym:...` runs Gym through uv, which provides the Python 3.13.14 or newer that nemo-gym needs. Gym builds an
environment for each server, in `work/gym/venvs/`; both of ours install this repository's package.
[`pyproject.toml`](pyproject.toml) here is only a marker that makes Gym install their `requirements.txt` as written.
