# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The knowledge base behind the PrimeVul agents' `search_security_kb` tool.

Two sources, one document each: the CWE weakness definitions (`cwe_reference.json`, shipped here) and the rules of
the SEI CERT C Coding Standard (downloaded at a pinned commit). They live in one Qdrant collection, with a dense and a
sparse (BM25) vector per document.

- `sources`: reading the two sources into chunks; the pinned commit and model revisions;
- `mapping`, `sanitize`: chunk to Haystack `Document`, with the third-party text scrubbed on the way in;
- `store`: the Qdrant collection and the record of what built it;
- `build`: fetch, embed and write (`security-agent primevul kb build`);
- `search`: `SecurityKbSearch`, the tool's component: a retrieval sub-agent (the Haystack agent pack's Advanced RAG
  Agent) over hybrid retrieval and a cross-encoder rerank, which writes a short, cited briefing;
- `prompts`, `render`: the sub-agent's system prompt, and the briefing as the outer agent sees it.

The module names are part of the agent files (`security_agent.knowledge_base.search.SecurityKbSearch`).
"""
