# Documentation

- [`synthetic.md`](synthetic.md): the runbook for the synthetic custom-component benchmark. Serve Qwen3.8 Flash-Next
  with vLLM, create the OpenShell sandbox, scan with the seed and the looped agent, run the self-improvement loop, and
  deploy an approved agent into the sandbox.

Planned pages:

- `setup-dgx-spark.md`: from a fresh DGX Spark to a served model.
- `primevul.md`: the runbook for PrimeVul. Build the data and the knowledge base, and evaluate the agents with a script
  or as NeMo Gym rollouts. Run the prompt loop from the seed, and train the distilled adapter.
- `architecture.md`: how the pieces connect, and which of them produced which result.

For each step, the runbooks give the command, its runtime on one DGX Spark and what to expect, including the
run-to-run noise.
