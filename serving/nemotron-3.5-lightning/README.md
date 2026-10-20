# Nemotron 3.5 Lightning on NVIDIA NIM

NVIDIA's stock NIM container for Nemotron 3.5 Lightning (30B-A3B) with its NVFP4 profile: vLLM 0.25.1 inside, 8
parallel sequences, a 131,072-token context, prefix caching and no speculative decoding. It serves the model as
`nemotron-3.5-lightning` on `http://127.0.0.1:8000/v1`.

## Run it

Needs Docker with the NVIDIA runtime, Hatch, and an NGC API key from [ngc.nvidia.com](https://ngc.nvidia.com). From
the repository root:

```sh
export NGC_API_KEY=...                 # or put it in .env, see .env.example
hatch run serving:lightning setup      # once: log in to nvcr.io, download the profile (about 24 GB)
hatch run serving:lightning start      # waits until the model answers, about 4 minutes
hatch run serving:smoke
hatch run serving:lightning stop
```

## What is pinned

| | |
|---|---|
| Image | `nvcr.io/nim/nvidia/nemotron-3.5-lightning-30b-a3b:2.0.9-variant`, digest `sha256:c2b2138e056d…`, the image our runs used. The `latest` tag now points to a newer build. |
| Profile | `920207996e4ec77b396e25f4e360ac80331a67dcae0fec428803f556afe1d47c`, `vllm-nvfp4-tp1-pp1` |
| Cache | `~/.cache/nim` (`NIM_CACHE`) and `~/.local/share/nim/workspace` (`NIM_WORKSPACE`) |

## Settings that matter

- **`NIM_PASSTHROUGH_ARGS`.**  Only arguments passed through `NIM_PASSTHROUGH_ARGS` reach vLLM, and without them every tool call
  fails. `serve.sh` passes:
  - `--reasoning-parser nemotron_v3`, so the thinking arrives in its own field and not in the answer;
  - `--enable-auto-tool-choice --tool-call-parser qwen3_coder`, which matches the model's chat template;
  - `--max-num-seqs 8`.
- **Thinking budget:** the same request fields as for vLLM, `"thinking_token_budget"` and
  `"chat_template_kwargs": {"enable_thinking": false}`. When the budget cuts its reasoning short, Lightning finishes
  its thought visibly in the answer, so use a JSON schema where the answer must be structured.

## What we measured

- About 83 output tokens per second for one stream without speculative decoding.
- Ready about 4 minutes after `start`. On the Spark's unified memory, the NIM limits itself to half of the GPU memory,
  about 70 GB in use.
