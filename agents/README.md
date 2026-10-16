# Agents

The agents behind the results, as Haystack YAML. Treat them as code, see [SECURITY.md](../SECURITY.md).

Planned:

- `synthetic/seed/` and `synthetic/looped/`: the repository scan agent before and after the self-improvement loop.
  Each is a Haystack pipeline around an `Agent`; load it with `Pipeline.loads`. The looped agent's `tools/` folder
  holds the Python tools and steps the optimizer wrote.
- `primevul/seed/` and `primevul/looped/`: the Flash-Next agent with the knowledge-base tool, before and after the
  prompt loop. Load them with `Agent.from_dict`.

Each folder has a short note, in plain language, on what changed against the seed.

Two PrimeVul results have no agent file. Deductive + examples is a prompt plus retrieved examples, set up by a script.
The distilled Nemotron is a model adapter. The PrimeVul runbook covers both.
