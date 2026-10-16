# Qwen3.8 Flash-Next on vLLM

The [UltraFast recipe](https://github.com/dime-online/qwen3.8-Flash-DGX-UltraFast) (Apache-2.0) for the DGX Spark: vLLM
with a W4A16 AutoRound checkpoint, an FP8 side table, a dense MTP drafter proposing 3 tokens per step, 8 parallel
sequences, a 262,144-token context and prefix caching. It serves the model as `qwen3.8-flash-next` on
`http://127.0.0.1:8000/v1`.

## Run it

Needs Docker with the NVIDIA runtime, `git`, `jq`, `curl`, Hatch, and about 140 GB of free disk under `~/models` plus
the images. Hatch's `serving` environment provides the Hugging Face CLI `hf` that `setup` downloads with. From the
repository root:

```sh
hatch run serving:flash-next setup     # once: pinned downloads and two image builds; safe to run again
hatch run serving:flash-next start     # waits until the model answers, about 4 to 7 minutes
hatch run serving:smoke
hatch run serving:flash-next stop
```

`serve.sh` also runs on its own (`serving/qwen3.8-flash-next/serve.sh start`); only `setup` needs `hf` on the PATH.

## What is pinned

| | |
|---|---|
| Recipe | `dime-online/qwen3.8-Flash-DGX-UltraFast` at `0c391a3`, config `v16b`, cloned to `~/qwen3.8-Flash-DGX-UltraFast` (`RECIPE_DIR`) |
| Image | `qwen38-flash-dgx:iter6d-20260910`, built by the recipe from a digest-pinned `vllm/vllm-openai` parent image |
| Checkpoint | `Saren/Qwen3.8-Flash-Next-W4A16-AutoRound-hybrid` at `8b82f0b`, converted by the recipe into the dense-MTP drafter directory |
| FP8 table | `Saren/Qwen3.8-Flash-Next-ple-table-fp8` at `50511b0` |

[`ultrafast-0c391a3.patch`](ultrafast-0c391a3.patch) holds our changes to the recipe:
- the server listens on loopback only; as shipped, it is published on every interface;
- the model name is `qwen3.8-flash-next` instead of `qwen`;
- the drafter build runs its CPU test gates from `/tmp`. As shipped, they write into a read-only mount and the build
  fails.

## Using it

- **Set a thinking budget on every request:** `"thinking_token_budget": 2048` in the request body (in Haystack's
  generators, under `extra_body`). Without one, the model thought for 8,000 tokens and never answered. The server gives
  no "budget reached" signal, so keep budgets generous: at 64 tokens it still answers, but worse.
- **Thinking off:** `"chat_template_kwargs": {"enable_thinking": false}`.
- **Structured answers:** a JSON schema in `response_format` is honored, but only on calls without tools. The model
  does not see the schema, so explain every field in the prompt.
- **API:** chat completions. Tool calls use vLLM's `qwen3_xml` parser, and reasoning arrives in its own field.

## What we measured

- About 140 to 160 output tokens per second in aggregate at 8 parallel requests, about 20 per request.
- About 96 GB resident, so nothing else large runs beside it.
- Ready 4 to 7 minutes after `start`.
