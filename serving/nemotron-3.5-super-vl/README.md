# Nemotron 3.5 Super VL on vLLM

NVIDIA Nemotron 3.5 Super VL (120B parameters, 12B active per token) in its NVFP4 checkpoint, on the vLLM nightly that
the [model card](https://huggingface.co/nvidia/NVIDIA-Nemotron-3.5-Super-VL-120B-A12B-NVFP4)'s DGX Spark recipe names:
8 parallel sequences, the model's own multi-token prediction proposing 3 tokens per step, a 262,144-token context and
prefix caching. It serves the model as `nemotron-3.5-super-vl` on `http://127.0.0.1:8000/v1`, text only.

## Run it

Needs Docker with the NVIDIA runtime, `curl`, Hatch, and about 80 GB of free disk under `~/models` plus the image.
Hatch's `serving` environment provides the Hugging Face CLI `hf` that `setup` downloads with. From the repository root:

```sh
hatch run serving:super-vl setup     # once: the image and the checkpoint (about 70 GB); safe to run again
hatch run serving:super-vl start     # waits until the model answers, about 13 minutes
hatch run serving:smoke
hatch run serving:super-vl stop
```

`serve.sh` also runs on its own (`serving/nemotron-3.5-super-vl/serve.sh start`); only `setup` needs `hf` on the PATH.

## What is pinned

| | |
|---|---|
| Image | `vllm/vllm-openai:nightly-3f1bcfd82bb2e93fcd364fc7a5491718453a77e2`, digest `sha256:cb9bc64f0f03…` (vLLM 0.32.0rc1.dev190) |
| Checkpoint | `nvidia/NVIDIA-Nemotron-3.5-Super-VL-120B-A12B-NVFP4` at `579ffa0`, in `~/models/nemotron-3.5-super-vl-nvfp4` |

## Settings that differ from the model card

- **8 parallel sequences with multi-token prediction** instead of one sequence with a separate draft model. One
  sequence is fastest for one user, but far too slow for a benchmark that scans many repositories in parallel.
- **A 262,144-token context.** Scans stay below 64,000 tokens, but the optimizer's requests grow past 150,000.
- **80% of the GPU memory.** At 85% with this context, the engine was killed for lack of memory once it had reserved
  its cache.
- **No images or video,** so the vision encoder's buffers are not reserved.

## Using it

- **Thinking:** `"thinking_token_budget"` in the request body caps it, and `"chat_template_kwargs": {"enable_thinking":
  false}` turns it off, as for the other models. Set a budget on every request: without one, thinking ran past 4,000
  tokens on a small arithmetic question.
- **Use temperature 0 with a thinking budget.** On this vLLM build, a thinking budget and a temperature above 0 lose the
  answer: the call runs on until `max_tokens` and returns nothing visible. The model config
  ([`model.yaml`](../../src/security_agent/synthetic/config/model.yaml)) sets `greedy_with_thinking_budget: true`, so
  every call with a budget runs at temperature 0, the optimizer's too.
- **Empty answers.** Now and then the model replies with reasoning only, no text and no tool call. The scan agent asks
  again once, then ends its turn.
- **API:** chat completions. Tool calls use vLLM's `qwen3_coder` parser, and reasoning arrives in its own field
  (`nemotron_v3` parser).

## What we measured

- About 120 output tokens per second in aggregate at 8 parallel requests, and 1,800 to 2,600 prompt tokens per second
  under load.
- About 110 GB of the Spark's memory in use, so nothing else large runs beside it.
- Ready about 13 minutes after `start`.
- **Heat.** Under a full benchmark load the GPU peaked at 79 °C. A single DGX Spark has been reported to switch itself
  off during long prefills at 82 to 85 °C; if yours runs hotter, lower `--max-num-seqs` (and `concurrency` in the model
  config with it).
