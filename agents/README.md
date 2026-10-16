# Agents

Agent configurations as Haystack YAML. Load them with `Agent.from_dict`. Treat them as code, see
[SECURITY.md](../SECURITY.md).

Planned:

- `seed/`: the simple seed agent the loop starts from.
- `controls/`: the fixed agents used for comparison. Deductive prompt (C), the same with repository context (R), and
  the same with retrieved training examples (K).
- `self-improved/`: the agents the loop produced. Each folder has the YAML, the diff against the seed, the
  optimizer's rationale, and the source of any tool the optimizer wrote, extracted for reading.

A tool the optimizer writes is stored as a `MontySourceTool` entry in the YAML; its Python source is in the `source`
field.
