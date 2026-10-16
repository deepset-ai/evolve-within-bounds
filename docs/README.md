# Documentation

Planned pages:

- `architecture.md`: how the pieces connect: the Haystack agent inside the OpenShell sandbox, the model server
  (vLLM or NIM), the knowledge base, the Monty sandbox for model-written tools, and NeMo Gym.
- `setup-dgx-spark.md`: from a fresh DGX Spark to a served model and a running agent.
- `self-improvement.md`: the loop. The seed agent, the optimizer, the gates, the validation check, and its modes:
  prompt only, tool only, and tool plus prompt.
- `reproducing-results.md`: for each reported number, the command, its runtime on one DGX Spark, the expected value
  and its run-to-run noise.
- `experiments/`: the pre-registrations and results, one file per round.
