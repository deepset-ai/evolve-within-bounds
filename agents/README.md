# Agents

The agents behind the results, as Haystack YAML. Treat them as code, see [SECURITY.md](../SECURITY.md).

- [`synthetic/seed/`](synthetic/seed/) and [`synthetic/looped/`](synthetic/looped/): the repository scan agent
  before and after the self-improvement loop. Each is a Haystack pipeline around an `Agent` (`pipeline.yaml`, whose
  header says what it is), with its prompts. The looped agent's `tools/` folder holds the Python tools and pipeline
  steps the optimizer wrote. Run them with `security_agent.synthetic`, inside the OpenShell
  sandbox: [`docs/synthetic.md`](../docs/synthetic.md).
- [`primevul/seed/`](primevul/seed/) and [`primevul/looped/`](primevul/looped/): the PrimeVul triage agent before
  and after the prompt loop, a serialized Haystack `Agent` (`agent.yaml`) with one tool, `search_security_kb`. The loop
  changed its system prompt and the tool's description. Load them with `Agent.from_dict`, or run them with
  `security_agent.primevul`: [`docs/primevul.md`](../docs/primevul.md).
