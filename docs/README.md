# Documentation

Planned pages:

- `setup-dgx-spark.md`: from a fresh DGX Spark to a served model.
- `synthetic.md`: the runbook for the synthetic custom-component benchmark. Serve Qwen3.8 Flash-Next with vLLM, scan
  with the seed and the looped agent, score both, and run the self-improvement loop. Then approve an improvement and
  deploy it into the OpenShell sandbox.
- `primevul.md`: the runbook for PrimeVul. Build the data and the knowledge base, and evaluate the agents with a script
  or as NeMo Gym rollouts. Run the prompt loop from the seed, and train the distilled adapter.
- `architecture.md`: how the pieces connect, and which of them produced which result.

For each step, the runbooks give the command, its runtime on one DGX Spark and what to expect, including the
run-to-run noise.
