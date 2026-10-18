# Results: PrimeVul

The prompt loop turned the starting triage agent into a more careful reviewer. On 100 held-out test pairs it gets 21
pairs right instead of 16, and it calls the patched function vulnerable in 58.5% of the pairs instead of 75.0%. The
optimizer wrote the new prompt itself, from what the agent did on training pairs, within fixed gates and without a
person editing the agent.

The benchmark is [PrimeVul](https://github.com/DLVulDet/PrimeVul), paired (files in
[`data/primevul/`](../data/primevul/)); the runbook to rerun it is [`docs/primevul.md`](../docs/primevul.md).

## The agents

Both are a Haystack `Agent` on Qwen3.8 Flash-Next that judges one C/C++ function at a time and answers with a JSON
verdict. Each has one tool, `search_security_kb`: a retrieval sub-agent over the CWE definitions and the SEI CERT C
rules that writes a short, cited briefing.

- **seed** ([`agents/primevul/seed/`](../agents/primevul/seed/)): a short prompt. Decide from the code alone; only
  for a function judged vulnerable, ask the tool which CWE fits.
- **looped** ([`agents/primevul/looped/`](../agents/primevul/looped/)): what two runs of the prompt loop made of the
  seed. The optimizer rewrote the system prompt (2,100 to 6,800 characters) and the tool's description, nothing else:
  - **a procedure:** find the externally controlled inputs, the operations they reach, and the checks on every path
    between them; call a function vulnerable only when the verdict can name the value, the line, the consequence and
    the check that is missing;
  - **an evidence standard:** no defect that rests on guesses about code the agent cannot see, such as what an unseen
    callee does or whether some other routine freed an object first; a check that is present counts; one concrete
    scenario, not re-aimed when a guard refutes it;
  - **the tool only to name a defect already found:** one abstract question about the weakness pattern, never a search
    for further bugs; a briefing that describes another defect is not evidence about this function.

Both ran at temperature 0, with at most 2,048 reasoning tokens per reply, and the same knowledge base (1,091 documents:
969 CWE entries and 122 CERT C rules; `hatch run primevul:kb build` rebuilds it document for document).

## Numbers

A pair is **right** when the agent calls the vulnerable function vulnerable and its patched twin benign; each function
is judged alone. This is paired accuracy, the number on the talk's slide. The test pairs are the first 100 pairs of
PrimeVul's paired test split; one run per agent.

| First 100 test pairs | seed | looped |
|---|---|---|
| **Pairs right** | 16 | **21** |
| Pairs whose twins got different verdicts | 23 | **30** |
| ... of those, the right way round | 70% | 70% |
| **Patched twin called vulnerable, of the pairs with both verdicts** | 75.0% (72 of 96) | **58.5% (55 of 94)** |
| Patched functions called vulnerable, of those with a verdict | 76% | 59% |
| Both twins called vulnerable (`missed_fix`) | 65 | **46** |
| Both called benign (`missed_bug`) | 8 | 18 |
| The wrong way round (`inverted`) | 7 | 9 |
| A function without a verdict (`parse_error`, pairs) | 4 | 6 |
| Knowledge-base calls, for 200 functions | 351 | **297** |
| Median seconds per function | 421 | 443 |

Between the two runs of the loop, the first run's pick got 20 of these pairs right, with the patched twin called
vulnerable in 64% of the functions; every step moved the same way.

## What the loop changed

- **More pairs right on held-out pairs:** 16 to 21 on test. Each loop run had checked its pick against its starting
  agent on validation pairs first: 5 to 6 of 30 in the first run, 9 to 15 of 50 in the second.
- **Far fewer false alarms.** The seed called both twins vulnerable in 65 of 100 pairs: it noticed a risky operation
  and did not weigh the check the patch adds. The looped agent does so in 46, and the share of pairs whose patched twin
  it flags falls from 75.0% to 58.5%.
- **Twins told apart more often:** the two functions of a pair got different verdicts in 30 pairs instead of 23, at the
  same right-way rate.
- **A leaner procedure:** 15% fewer knowledge-base calls, at about the same time per function.
- **Built by the optimizer, inside the bounds.** The optimizer read the failing training pairs, the patch between their
  twins and what the agent and its sub-agent did on each; it could change only the prompt, the tool's description and
  the budgets; candidates that copied code or function names from the training pairs were refused; and a candidate
  counted only if it ranked above its starting agent on the training pairs and then got more validation pairs right.


To rerun the test numbers: steps 1 to 4 of the [runbook](../docs/primevul.md).
