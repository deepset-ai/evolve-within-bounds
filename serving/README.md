# Serving

One folder per model. Each has a README with the pinned model revision, the container image digest and the speed we
measured, a `serve.sh` (loopback only; `NO_SPEC=1` turns speculative decoding off), and a Dockerfile where the image
needs one.

Planned: `qwen3.8-flash-next/`, `nemotron-3.5-lightning/`, `nemotron-3.5-bolt/`, `nemotron-3.5-super-vl/`, `nim/`.

Only one of these models fits in the DGX Spark's memory at a time.
