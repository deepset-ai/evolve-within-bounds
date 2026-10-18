# Serving

One folder per model. Each has a README with the pinned model revision and container image, the results it served,
and a `serve.sh` (`setup`, `start`, `stop`, `status`, `logs`) that listens on `127.0.0.1:8000`. When OpenShell is
installed, it also listens on the gateway of OpenShell's Docker bridge, so that the agent in the sandbox reaches it
([`sandbox/`](../sandbox/)); that address is not reachable from the network. Run it through Hatch's `serving`
environment, which also provides the tools `setup` needs:

| Folder | Server | Command | Serves |
|---|---|---|---|
| [`qwen3.8-flash-next/`](qwen3.8-flash-next/) | vLLM, with the UltraFast recipe | `hatch run serving:flash-next <command>` | the synthetic custom-component benchmark and PrimeVul |
| [`nemotron-3.5-lightning/`](nemotron-3.5-lightning/) | NVIDIA NIM | `hatch run serving:lightning <command>` | none of the numbers in [`results/`](../results/) |

Only one of these models fits in the DGX Spark's memory at a time, and both use port 8000.

## Smoke check

Run it after a server starts and before any benchmark run:

```sh
hatch run serving:smoke                          # the model on 127.0.0.1:8000
hatch run serving:smoke --report smoke.json      # also write every check's details
```

It checks what the agents rely on: a plain answer, reasoning in its own field, a per-request thinking budget that
binds and holds, answers that follow a JSON schema, a tool call with a long argument, a short tool loop over a sample
repository, and 8 parallel requests. It uses only the Python standard library, so
`python3 -m security_agent.serving.smoke` with `src/` on `PYTHONPATH` works without Hatch.

## Qdrant

[`qdrant/compose.yaml`](qdrant/compose.yaml) runs Qdrant 1.19.0, the document store of the PrimeVul agents' knowledge
base, on `127.0.0.1:6333`: `hatch run primevul:qdrant up -d`. It needs no GPU. See [`docs/primevul.md`](../docs/primevul.md).
