# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The synthetic custom-component benchmark: the repository scan agent, and the task the shared loop improves it on.

- `agent`: the scanner, a Haystack pipeline around an Agent, extended with tools and steps the optimizer writes;
- `bench`: scanning the benchmark, journaling each scan, scoring with the benchmark's own scorer;
- `task`: the benchmark as a task for the loop (`security_agent.optimize`): measuring, failure digests (`digest`), the
  optimizer's tools (`examples`, `traces`);
- `sandbox`: running scans, and the optimizer's code, inside an NVIDIA OpenShell sandbox;
- `staging`: the copy of a repository a scan sees: no files that give the answer away, fixed metadata, a random path;
- `cli`: `security-agent synthetic ...`.

`config/` holds the model server, benchmark, split and loop settings; `prompts/optimizer.md` the optimizer's prompt.
The runbook is docs/synthetic.md.
"""
