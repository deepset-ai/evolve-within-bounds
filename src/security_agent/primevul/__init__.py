# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
PrimeVul: the triage agent that judges one function at a time, run and scored per pair.

- `tasks`: the benchmark file (data/primevul/build/), one task per function, and the pairs;
- `verdict`: the agent's answer as a verdict;
- `agent`: loading an agent file, and the two fallbacks for an answer that went missing;
- `scoring`: a label per pair, and the metrics;
- `measure`: running an agent over the tasks, resumably;
- `task`: PrimeVul as a task for the shared loop (`security_agent.optimize`): the prompt loop;
- `sandbox`: judging functions inside an NVIDIA OpenShell sandbox;
- `cli`: `security-agent primevul ...`.

The agents are in agents/primevul/, their knowledge-base tool is `security_agent.knowledge_base`. The runbook is
docs/primevul.md.
"""
