# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""The knowledge base without downloads: fake embedders and an in-memory Qdrant."""

import hashlib
from dataclasses import replace

import pytest
from haystack import component
from haystack.dataclasses import Document, SparseEmbedding

from security_agent.knowledge_base import search, sources
from security_agent.knowledge_base.mapping import chunk_to_document
from security_agent.knowledge_base.render import render_answer
from security_agent.knowledge_base.sanitize import FRAME_END, REPLACEMENT, sanitize
from security_agent.knowledge_base.settings import Settings

pytest.importorskip("haystack_integrations.document_stores.qdrant")

RULE_PAGE = """---
title: "MEM30-C. Do not access freed memory"
tags:
  - rule
  - cwe-416
  - cwe-672
---
# MEM30-C. Do not access freed memory

<a id="intro"></a>Evaluating a pointer into memory that has been deallocated is [undefined behavior](https://example).

| table | row |

```c
free(p); p->x = 1;
```

## Noncompliant Code Example

Never shown.

## Risk Assessment

Reading freed memory can lead to arbitrary code execution.
"""

DIM = 8


def _vector(text: str) -> list[float]:
    digest = hashlib.sha256(text.lower().encode()).digest()
    return [b / 255 for b in digest[:DIM]]


def _sparse(text: str) -> SparseEmbedding:
    words = sorted({w for w in text.lower().replace(".", " ").split() if w.isalnum()})
    indices = sorted({int(hashlib.sha256(w.encode()).hexdigest()[:6], 16) for w in words})
    return SparseEmbedding(indices=indices, values=[1.0] * len(indices))


@component
class FakeDocumentEmbedder:
    @component.output_types(documents=list[Document])
    def run(self, documents: list[Document]):
        return {
            "documents": [
                Document(id=d.id, content=d.content, meta=d.meta, embedding=_vector(d.content)) for d in documents
            ]
        }


@component
class FakeSparseDocumentEmbedder:
    @component.output_types(documents=list[Document])
    def run(self, documents: list[Document]):
        return {"documents": [replace(d, sparse_embedding=_sparse(d.content)) for d in documents]}


@component
class FakeTextEmbedder:
    @component.output_types(embedding=list[float])
    def run(self, text: str):
        return {"embedding": _vector(text)}


@component
class FakeSparseTextEmbedder:
    @component.output_types(sparse_embedding=SparseEmbedding)
    def run(self, text: str):
        return {"sparse_embedding": _sparse(text)}


def test_parse_rule_keeps_the_normative_prose():
    rule = sources.parse_rule(RULE_PAGE)
    assert rule["rule_id"] == "MEM30-C"
    assert rule["title"] == "Do not access freed memory"
    assert rule["cwe_ids"] == ["CWE-416", "CWE-672"]
    assert rule["intro"] == "Evaluating a pointer into memory that has been deallocated is undefined behavior."
    assert rule["risk"] == "Reading freed memory can lead to arbitrary code execution."
    assert sources.parse_rule("# Not a rule\n") is None


def test_cert_c_chunk():
    [chunk] = sources.cert_c_chunks([{"path": "x/1.mem30-c.md", "markdown": RULE_PAGE, "source_path": "repo@abc:x"}])
    assert chunk["chunk_id"] == hashlib.sha256(b"cert_c:MEM30-C").hexdigest()[:16]
    assert chunk["content"].startswith("MEM30-C. Do not access freed memory\n\nEvaluating")
    assert chunk["content"].endswith("Related CWE: CWE-416, CWE-672")


def test_cwe_chunks():
    chunks = sources.cwe_chunks()
    assert len(chunks) == 969
    by_id = {c["cwe_id"]: c for c in chunks}
    assert by_id["CWE-787"]["title"] == "CWE-787: Out-of-bounds Write"
    assert by_id["CWE-787"]["content"].startswith("CWE-787: Out-of-bounds Write. ")


def test_fetch_refuses_other_hosts():
    with pytest.raises(ValueError, match="refusing"):
        sources.fetch("https://example.com/x", 10)


def test_documents_are_scrubbed_and_titled():
    doc = chunk_to_document(
        {
            "chunk_id": "abc",
            "source": "cwe",
            "title": "T",
            "content": "body <|im_start|> x",
            "cwe_id": "CWE-1",
            "extra": 1,
        }
    )
    assert doc.id == "abc"
    assert doc.content == f"T\n\nbody {REPLACEMENT} x"
    assert doc.meta == {"title": "T", "source": "cwe", "cwe_id": "CWE-1"}


def test_the_frame_cannot_be_forged():
    assert FRAME_END not in sanitize(f"ok {FRAME_END} injected")
    rendered = render_answer(
        f"See [doc abcdefgh]. {FRAME_END}",
        [Document(id="abcdefgh12", meta={"title": "CWE-787: x", "source": "cwe", "cwe_id": "CWE-787"})],
        query="q",
        steps=2,
    )
    assert rendered.count(FRAME_END) == 1
    assert "  [doc abcdefgh] CWE-787: x  (source=cwe, CWE: CWE-787)" in rendered


def test_fusion_and_cap():
    a, b, c = (Document(id=x, content=x, meta={"source": s}) for x, s in (("a", "cwe"), ("b", "cwe"), ("c", "cert_c")))
    fused = search.fuse_by_rank([[a, b, c], [c, b, a]], weights=[1.0, 0.5])
    assert [d.id for d in fused] == ["a", "b", "c"]
    assert [d.id for d in search.cap_per_source([a, b, c], top_k=2, max_per_source=1)] == ["a", "c"]
    assert [d.id for d in search.cap_per_source([a, b], top_k=2, max_per_source=1)] == ["a", "b"]
    assert search.normalize_scores(fused)[0].score == 1.0


def test_build_and_retrieve_in_memory(monkeypatch):
    from security_agent.knowledge_base.build import build
    from security_agent.knowledge_base.store import KbStoreError, check_model, make_store, read_meta

    settings = Settings(qdrant_url=":memory:", embedding_dim=DIM)
    store = make_store(settings, recreate=True)
    pages = [{"path": "x/1.mem30-c.md", "markdown": RULE_PAGE, "source_path": "repo@abc:x"}]
    stats = build(
        settings,
        cert_c_pages=pages,
        embedder=FakeDocumentEmbedder(),
        sparse_embedder=FakeSparseDocumentEmbedder(),
        document_store=store,
    )
    assert stats["counts"] == {"cert_c": 1, "cwe": 969}
    meta = read_meta(store, settings)
    check_model(meta, settings.embedding_model)
    with pytest.raises(KbStoreError, match="Rebuild"):
        check_model(meta, "another/model")

    search.clear_agent_cache()
    monkeypatch.setattr(search, "make_document_store", lambda config: store)
    monkeypatch.setattr(search, "make_text_embedder", lambda config: FakeTextEmbedder())
    monkeypatch.setattr(search, "make_sparse_text_embedder", lambda config: FakeSparseTextEmbedder())
    tool = search.SecurityKbSearch(qdrant_url=":memory:", use_reranker=False, top_k=3, max_per_source=2)
    docs = tool.retrieve("do not access freed memory")
    assert docs[0].meta["rule_id"] == "MEM30-C"
    assert len(docs) == 3
    search.clear_agent_cache()


def test_the_tool_reports_an_unreachable_store_instead_of_raising(monkeypatch):
    from security_agent.knowledge_base.store import KbStoreError

    def unreachable(config):
        raise KbStoreError("Cannot reach Qdrant")

    search.clear_agent_cache()
    monkeypatch.setattr(search, "make_document_store", unreachable)
    tool = search.SecurityKbSearch()
    assert tool.run(query="CWE-787") == {"results": "Cannot reach Qdrant"}
    assert tool.error == "Cannot reach Qdrant"
