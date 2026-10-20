# The GUI

A web page for showing the project. Four tabs:

1. **How the agent evolved:** a self-improvement loop run, version by version: pairs right on the training pairs and
   on the validation pairs, the best so far, and the agent it picked with its test result. The data is
   [`evolution.json`](evolution.json): aggregate counts over all the pairs the loop ran on, our public synthetic
   benchmark and two we can't publish. It is an earlier run, on Qwen3.8 Flash-Next;
   [`results/synthetic.md`](../results/synthetic.md) and [`agents/synthetic/looped`](../agents/synthetic/looped/) are
   from a later one, on Nemotron 3.5 Super VL.
2. **Watch it improve:** the live demo ([`demo/README.md`](../demo/README.md)) in the page, as the terminal shows it, next
   to a plain-language list of its steps. At rest the terminal holds the run recorded in
   [`demo/recording/`](../demo/recording/), and each step opens its part. The visitor clicks Approve or Decline when the
   demo asks. Without a model server or sandbox, "Play the recording" plays the recorded run instead, with the same
   approval step.
3. **Scan an integration:** integrations from
   [haystack-core-integrations](https://github.com/deepset-ai/haystack-core-integrations), Haystack's connectors to
   model providers, databases and tools, at the commit pinned in [`integrations.yaml`](integrations.yaml). The visitor
   picks one and sees what the evolved agent ([`agents/synthetic/looped`](../agents/synthetic/looped/)) reported
   when it scanned it inside the sandbox: the findings one at a time, each with its code, what the agent noticed, why
   it matters and the call to check, or that it reported nothing; and the files it read, with the scan's steps and time.
4. **Spot the vulnerability:** pairs of real C functions from [PrimeVul](https://github.com/DLVulDet/PrimeVul), chosen
   in [`pairs.yaml`](pairs.yaml): a function as it was before a public security fix, and the patched version, side by
   side with the lines that differ marked. The visitor guesses which one is vulnerable; the page then shows which it
   was, the PrimeVul agent's verdict on each function with its reason and the lines it pointed at, and whether the pair
   came out right (both verdicts must be). The numbers in the tab's introduction are those of
   [`results/primevul.md`](../results/primevul.md).

## Running it

On the DGX Spark, with the demo set up ([`demo/README.md`](../demo/README.md), "Before the talk"):

```bash
hatch run synthetic:gui                    # http://127.0.0.1:8765
hatch run synthetic:gui --host 0.0.0.0     # to open the page from another machine on the network
```

**The integrations, before they are shown.** This is real code, so a scan can turn up a real vulnerability nobody has
reported yet, and that must not go up on a screen in front of an audience. So nothing is scanned live: the integrations are
scanned once beforehand, a person reads every finding, and the page shows only the integrations they approved.

```bash
hatch run synthetic:gui --prepare                 # clones the repository at the pinned commit, scans every integration
hatch run synthetic:gui --review                  # every integration's findings, for the person who reviews them
hatch run synthetic:gui --approve ollama qdrant --by "Your Name"   # puts these on the page
hatch run synthetic:gui --revoke qdrant           # takes one off again
```

**The pairs.** `hatch run synthetic:gui --prepare-pairs` copies the chosen pairs out of the benchmark file
(`hatch run primevul:build`, [`docs/primevul.md`](../docs/primevul.md)) into `work/gui/` and judges their functions
with the PrimeVul agent through `hatch run primevul:run`, four at a time, into `runs/gui/pairs/`; it needs what any
PrimeVul run needs (the model server, the knowledge base's Qdrant, and the retrieval models: on a machine that can't
reach Hugging Face, `HF_HOME` pointing at a cache that holds them and `KB_OFFLINE=1`, as in
[`docs/primevul.md`](../docs/primevul.md)), and takes about 3 minutes per function. A pair appears
on the page once both of its functions are judged; the dataset is public, so there is nothing to approve. To change the
pairs, edit `pairs.yaml` and run `--prepare-pairs` again: an earlier run resumes, so only new functions are judged.
`--import-pairs <tasks.json>` takes the verdicts from an earlier run instead, the one behind
[`results/primevul.md`](../results/primevul.md) for instance, so the page shows the verdicts that were measured; the
pairs shipped in `pairs.yaml` were chosen from that run, six it got right and six it got wrong.

`--prepare` scans two integrations at a time (`--parallel`), each in about 5 to 10 minutes, and skips those scanned
before (`--rescan` scans them all again). An approval holds for the exact result that was reviewed: after a new scan,
the integration is off the page until it is approved again; a scan that did not finish cannot be approved. If a finding
looks real, don't approve it: report it as the project's
[`SECURITY.md`](https://github.com/deepset-ai/haystack-core-integrations/blob/main/SECURITY.md) asks. The checkout
is kept in `work/gui/`, the results and approvals in `runs/gui/integrations/`: both stay on the machine and out of
git.

Without the Spark (on a laptop, say), the page still works: the graph, the recording, and the integrations approved
on that machine. The header shows whether the model server and the sandbox are there.

**Unattended:** `http://127.0.0.1:8765/?autoplay` plays the recording in a loop, approving by itself after 5 seconds.
`#evolution`, `#demo` and `#scan` at the end of the address open a tab directly.

## How it works

[`server.py`](server.py) uses only the Python standard library and this repository's package. The live demo is
`demo/run_demo.sh` in a pseudo-terminal, so it prints its colours, streamed to the page as server-sent events; the
Approve button answers its prompt. A scan is `security-agent synthetic scan --candidate agents/synthetic/looped
--sandbox security-agent` on the integration's directory. The page ([`static/`](static/)) is plain HTML, CSS and
JavaScript, with no build step and nothing fetched from the internet; text the agent wrote is always shown as text.
It follows deepset's slide brand: the wordmark and the wave come from deepset's slide template, and the font is
[Inter](https://rsms.me/inter/), bundled in [`static/fonts/`](static/fonts/) under the SIL Open Font License
([`Inter-OFL.txt`](static/fonts/Inter-OFL.txt)).
