# Security Policy

## Report a Vulnerability

If you have found a security vulnerability in this repository, please report via email to
[opensource-security@deepset.ai](mailto:opensource-security@deepset.ai).

In your message, please include:

1. Reproducible steps to trigger the vulnerability.
2. An explanation of what makes you think there is a vulnerability.
3. Any information you may have on active exploitations of the vulnerability (zero-day).
4. An explanation of why you believe the vulnerability is not out of scope. See the Out of Scope section below.

We encourage reports that are meaningful, high-impact, and reviewed by a human before submission. Fully automated or
AI-generated reports submitted without human review and validation are unlikely to meet this bar and risk being declined.

## Trust Boundaries

The agent runs inside an OpenShell sandbox, created through NemoClaw, with proxy-only egress. Python code that a model
writes for the agent's tools runs in the Monty sandbox with time and memory limits. Model servers bind to the loopback
interface only.

## Out of Scope

### Agent configurations

Agent YAML files, including the tool source code stored in them, are executable configurations, like Haystack
pipelines. **Loading an agent configuration from an untrusted source is unsafe by design.** Treat agent YAML files as
code: review them before loading, and store and transmit them with the same controls as source code. Reports that rely
on an operator loading an untrusted agent configuration are out of scope.

### Third-party components

Vulnerabilities in vLLM, NVIDIA NIM, NemoClaw, OpenShell, Monty or the models themselves should be reported to their
maintainers. If our configuration of one of them weakens a boundary described above, that finding is in scope.

---

If you are uncertain whether a finding falls within scope, feel free to reach out before submitting a full report.

## Vulnerability Response

We aim to review your report within 5 business days where we do a preliminary analysis
to confirm that the vulnerability is plausible. Otherwise, we'll decline the report.

We won't disclose any information you share with us but we'll use it to get the issue
fixed or to coordinate a vendor response, as needed.

We'll keep you updated of the status of the issue.

Our goal is to disclose bugs as soon as possible once a user mitigation is available.
