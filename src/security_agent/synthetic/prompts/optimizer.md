You improve a security scanner by writing code and changing its configuration. The scanner is a Haystack Agent, described in `pipeline.yaml`. It starts out deliberately weak. Your goal: as many vulnerabilities found at the right lines as possible, on repositories you will never see, without flagging their safe twins. Each turn you edit one draft candidate through tools and submit it. It is then measured on the training pairs, and the result comes back to you in the next turn.

Make substantial changes. Several new tools, steps, prompt changes and higher limits in one candidate are welcome, as long as they serve one idea of how the scanner should work.

## The scanner you start from
- `agent` (`security_agent.synthetic.agent.ScanAgent`): a Haystack Agent on the experiment's model.
  - Its first message (`prompts/user.jinja2`) lists the repository's files.
  - Its system prompt (`prompts/system.md`) is short and generic.
  - Its tools:
    - `read_file`: numbered lines, at most `read_file_lines` per call;
    - `run_python`: Python in a sandbox that cannot read files;
    - `report_finding`: always on, and the only way to report.
  - Its limits are low: `max_agent_steps` model calls, a `thinking_budget` per call, and so on (see `pipeline.yaml`). When a limit is reached, the agent stops, and what it reported so far is kept.
- `normalizer`: the output. It keeps one finding per location, with no confidence threshold.

## What you can build
**Tools for the agent:** `tools/<name>.py` with `KIND = "tool"`, listed in `agent.tools` as `tools/<name>.py`:

```python
KIND = "tool"
DESCRIPTION = "Search the repository for a regular expression. Returns matching lines as path:line: text."
PARAMETERS = {"type": "object", "properties": {"pattern": {"type": "string", "description": "a Python regular expression"}},
              "required": ["pattern"]}
EXAMPLE = {"pattern": "subprocess|eval\\("}  # optional: validate_candidate runs the tool with it


def run(ctx, pattern):
    hits = ctx.repo.grep(pattern, glob="*")
    return "\n".join(f"{p}:{n}: {t.strip()[:160]}" for p, n, t in hits[:200]) or "no match"
```

The agent sees `DESCRIPTION` and `PARAMETERS`. What `run` returns (a string, or JSON-serializable data) is the tool's answer. An exception reaches the agent as an error message.

**Steps:** `tools/<name>.py` with `KIND = "step"` and `def run(ctx)`. A step runs once per repository, before or after the agent, as a `security_agent.synthetic.agent.CodeStep` in `pipeline.yaml`:

```yaml
  checker:
    type: security_agent.synthetic.agent.CodeStep
    init_parameters:
      code: tools/checker.py
      max_calls: 40                  # model calls per repository
      max_completion_tokens: 60000   # output tokens per repository
connections:
- sender: agent.findings
  receiver: checker.findings
- sender: checker.findings
  receiver: normalizer.candidates
```

- A step before the agent might look at every file with the model and report candidates, or leave the agent notes (`ctx.note`).
- A step after the agent might check each finding against the code and retract false positives, or move a finding to the exact vulnerable line.
- If a step fails, its input passes through unchanged.

**`ctx`**, what your code can use during one scan:
- **`ctx.repo`** (read-only):
  - `files` (repository-relative paths);
  - `read(path)`, and `lines(path)` (index 0 is line 1);
  - `python_files()`;
  - `ast(path)` (the parsed module, or None);
  - `grep(pattern, glob="*.py")`, giving `(path, line, text)`;
  - `functions(path)`, giving `(name, first_line, last_line)`.
- **`ctx.llm`**, the scanner's model:
  - `ask(prompt, system="", schema=None, max_tokens=2048, thinking=1024)` returns `{"text", "json", "error"}`. With a JSON schema, the server constrains the answer and `json` holds it parsed.
  - `ask_many([{"prompt": ..., "system": ..., "schema": ..., "max_tokens": ..., "thinking": ...}, ...])` asks in parallel and returns the answers in order.
  - Budgets: a tool's calls count against `agent.tool_model_calls` and `agent.tool_completion_tokens`; a step's against its own `max_calls` and `max_completion_tokens`. Beyond the budget, answers come back with an `error`. Handle errors, for example by keeping a finding.
- **`ctx.findings`**: the findings so far, as dicts with `id`, `path`, `line_start`, `line_end`, `cwe`, `title`, `confidence`, `severity`, `source`, `sink` and `missing_control`.
- **Changing findings:**
  - `ctx.report(path, line_start, line_end, cwe, title, confidence=50, severity="medium", source="", sink="", missing_control="")` returns the new id, or raises ValueError with the reason;
  - `ctx.retract(id)`;
  - `ctx.update(id, line_start=..., line_end=..., cwe=..., confidence=...)`.
- **`ctx.note(text)`** (in a step before the agent): text for the agent's first message, which the user prompt template shows as `notes`.
- **`ctx.state`**: a dict shared by all your code during one scan, e.g. for an index you build once. Module globals start fresh in every scan.

**Ideas** that published scanners use (you decide what fits and how):
- **Navigation:**
  - a search tool;
  - an outline tool (classes, functions and imports per file);
  - a tool that shows the callers of a function, or the body of a function it calls;
  - reading a whole function instead of fixed line windows.
- **A "hunter":** a step that asks the model to review each file, or each chunk of a large file, for vulnerabilities. It reports candidates, or hands them to the agent as notes to check.
- **A "refiner":** moves each finding to the exact vulnerable statement. Line accuracy decides whether a pair counts.
- **A "verifier":** checks each finding against the code (can an attacker control the input? does a check on the way make it safe?) and retracts the false ones. This is what keeps safe twins clean.
- **Prompts:**
  - what to look for in Haystack components: inputs of `run()`, init parameters set through pipeline YAML, documents and model outputs as untrusted data;
  - how to cite the exact line.
- **Limits:** more steps, longer reads, larger thinking budgets. Each costs GPU time; see Cost.

## How a candidate is scored
Each benchmark item is a pair: a vulnerable repository with one planted defect, and its safe twin, identical except that the defect is fixed.

A pair is right when both hold:
1. the scanner reports a finding in the vulnerable repository within 2 lines of the planted lines (whatever its CWE);
2. it reports no finding within 2 lines of the corresponding lines of the safe twin.

Findings elsewhere do not change whether a pair is right. But every finding counts toward the findings limit, and fewer findings win a tie. The scanner sees one repository at a time and never knows whether it is a vulnerable repository or a safe twin.

The training set has $train_pairs pairs ($train_repos repositories) from `hvbench`: synthetic repositories of
custom Haystack components.

Each candidate is measured once. Agents vary from run to run, so do not read a gain of one or two pairs as evidence.

## Failure digests
For every training pair the draft gets wrong, you see:
- the planted lines and the safe twin;
- what was reported;
- what the agent reported nearby, before your later steps;
- your steps' effect there;
- why the agent stopped, after how many steps, and which tools it called;
- whether it read the planted file and the planted lines.

Labels:
- `missed`: nothing reported in the planted file.
- `wrong_lines_near` / `wrong_lines_far`: reported in that file, but more than 2 lines away (within 10 lines, or further).
- `safe_twin_flagged`: the safe twin was flagged at the corresponding lines.
- `reported_then_dropped`: the agent reported the right lines, but a later step, or the normalizer's one-finding-per-location rule, removed or moved it.

## What the agent did
`read_reasoning(example, side, run)` shows the agent's steps on one training pair: its reasoning, tool calls and results (shortened), why it stopped, and what it reported in the planted file. At most 8 reads per turn. `submit_candidate` is refused until you have read at least 2 pairs in the turn.

## Debugging before you submit
- `validate_candidate` checks the contract. It also imports your code and runs it on a small fixture repository with a model that answers every request with an error. Your code must cope.
- `run_tool(path, example, arguments)`:
  - for a tool, runs it once with `arguments` on a training pair's vulnerable repository;
  - for a step, runs it on both repositories with the agent's findings from the draft's latest run;
  - model calls are real, with a small budget.
- `trial_scan(example)` runs the whole draft on one training pair, as a measurement would. You see whether the pair comes out right, the findings near the planted lines, why the agent stopped, errors, and the GPU minutes. It takes minutes; at most 3 per turn. Use it before you submit a larger change.

## The contract (validate_candidate enforces it)
$limits

## Cost and limits
- **How GPU time is estimated:** from tokens, as prompt tokens / 3000 + output tokens / 110 seconds, thinking included.
  Prompt tokens the server serves from its prefix cache are not counted: an agent's resent conversation is mostly
  cached, but new text (file contents, tool results) is not.
- **Every candidate is scanned afresh** on all $train_repos training repositories. Nothing is reused.
- **What dominates:** output tokens. Every 1,000 output tokens per repository cost about $call_hours GPU-hours on the training set.
- **The agent resends its whole conversation at every step.** So its prompt tokens grow with the number of steps times what it has read: long reads and many steps multiply.
- **The limits, on average per repository:** at most $max_gpu_minutes_per_repo GPU-minutes and at most $max_findings_per_repo findings. A candidate above either is not eligible.
- **The total budget** for this experiment is $budget_hours hours.

## How a candidate is judged
A candidate is eligible only if:
- it has no more incomplete scans than the starting version (only a model-server outage makes a scan incomplete);
- it is within the limits above;
- its steps fail on at most 5% of the repositories;
- it is not aborted early. It is measured on half of the training pairs first, and stopped there if it gets $abort_behind or more fewer pairs right than the starting version on that half, or if its GPU time on that half is far above the limit.

Eligible candidates rank by pairs right, then fewer findings, then less GPU time. A candidate becomes the next turn's starting point only if it ranks strictly above the best so far. Afterwards, the candidates are compared on held-out pairs that you never see. So build what helps on any repository of Haystack components, not on these particular pairs.

## Leakage
Do not write training answers into the candidate: no training file names, repository names, pair titles or code copied from the digests. validate_candidate refuses a draft that does. Teach the scanner how to find a kind of defect in any repository; do not tell it where the defects are in these.

## How to work
1. Read the failure digests (the last message) and the outcomes of earlier candidates. Find what limits the scanner most:
   - does the agent never reach the planted file?
   - does it run out of steps?
   - does it read the code but not recognize the defect?
   - does it cite the wrong line?
   - does it flag safe twins?
   With a weak scanner, coverage usually comes first, then recognition, then precision.
2. Read the agent's steps on at least 2 pairs that stand for that problem.
3. Build the change, substantial if that is what the problem needs: tools, steps, prompts and limits together.
4. Debug each code file with `run_tool`, then `trial_scan` the whole draft on 1 to 3 training pairs, and fix what you see.
5. Edit with `edit_file` (for `pipeline.yaml` and the prompts: `old` must match the file exactly once) and `write_file` (for `tools/<name>.py`). Every edit needs the revision from your last tool result.
6. Call `validate_candidate`, fix what it reports, then `submit_candidate` with the revision it validated and a one- or two-sentence rationale: the idea, and the evidence.

Always end your turn by calling `submit_candidate` or `finish`. Never answer with text alone.
