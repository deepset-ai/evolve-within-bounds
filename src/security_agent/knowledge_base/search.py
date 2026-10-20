# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
`search_security_kb`: a retrieval sub-agent over the knowledge base.

`SecurityKbSearch` is the component the agent files wrap as a `ComponentTool`. It owns an `Agent` built by the Haystack
agent pack's `create_advanced_rag_agent` (https://docs.haystack.deepset.ai/docs/advanced-rag-agent), which brings the
loop and five tools; this module brings the corpus, the retriever and the untrusted-content boundary:

    create_advanced_rag_agent(document_store=<Qdrant collection>, retriever=<pipeline below>)
      ├── list_metadata_fields / get_metadata_field_values / get_metadata_field_range
      ├── fetch_documents_by_filter
      └── search_documents, over

              dense_embedder  ─┐
                               ├─> QdrantHybridRetriever ─┬─> shaper
              sparse_embedder ─┘                          │
                               └─> ranker (cross-encoder) ┘

The outer agent gets a short, cited briefing (`render.render_answer`), not a list of chunks.

Two steps below the pack's tool boundary (`KbResultShaper`):

- The cross-encoder's order is fused with the retrieval order (weighted reciprocal rank fusion, the reranker at weight
  0.5) rather than replacing it: on this kind of corpus its scores saturate near 1.0, and on its own it buried exact
  lexical hits.
- At most `max_per_source` results per source, so the larger source cannot fill a whole result set.

The component builds everything in `warm_up()`, so deserializing an agent file loads no model and needs no Qdrant.
Built pipelines and sub-agents are cached per configuration and shared between threads; the transformer model calls
are serialized behind one lock.
"""

from __future__ import annotations

import collections
import json
import logging
import threading
import time
from typing import Any

from haystack import component, default_from_dict, default_to_dict
from haystack.dataclasses import ChatMessage, Document, SparseEmbedding

from security_agent.knowledge_base import prompts, render
from security_agent.knowledge_base.settings import Settings
from security_agent.knowledge_base.store import KbStoreError, check_model, make_store, read_meta

logger = logging.getLogger(__name__)

DEFAULT_QDRANT_URL = "http://localhost:6333"
DEFAULT_QDRANT_INDEX = "security_kb"
DEFAULT_SPARSE_MODEL = "Qdrant/bm25"
DEFAULT_EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
DEFAULT_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "
DEFAULT_RERANKER_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"
DEFAULT_LLM_MODEL = "gpt-5.4-mini"

# sentence-transformers' `encode` on a shared model is not documented as thread-safe, and the agents run tool calls
# concurrently. The lock covers the model calls only, so concurrent lookups still overlap on everything else.
_MODEL_LOCK = threading.Lock()

_PIPELINES: dict[tuple, Any] = {}
_AGENTS: dict[tuple, Any] = {}
_CACHE_LOCK = threading.Lock()

# The reciprocal rank fusion constant (Cormack et al. 2009).
RRF_K = 60


def clear_agent_cache() -> None:
    """Drop the cached pipelines and sub-agents (tests, and after a rebuild)."""
    with _CACHE_LOCK:
        _PIPELINES.clear()
        _AGENTS.clear()


def fuse_by_rank(orders: list[list[Document]], k: int = RRF_K, weights: list[float] | None = None) -> list[Document]:
    """Weighted reciprocal rank fusion of several orderings of the same documents; ties break on id."""
    weights = weights or [1.0] * len(orders)
    scores: dict[str, float] = {}
    documents: dict[str, Document] = {}
    for order, weight in zip(orders, weights, strict=False):
        for rank, doc in enumerate(order, start=1):
            scores[doc.id] = scores.get(doc.id, 0.0) + weight / (k + rank)
            documents.setdefault(doc.id, doc)
    ranked = sorted(documents.values(), key=lambda d: (-scores[d.id], d.id))
    return [Document(id=d.id, content=d.content, meta=dict(d.meta), score=scores[d.id]) for d in ranked]


def cap_per_source(documents: list[Document], top_k: int, max_per_source: int) -> list[Document]:
    """The best `top_k`, at most `max_per_source` from any one source; deferred ones fill up if there are too few."""
    if max_per_source <= 0:
        return documents[:top_k]
    kept: list[Document] = []
    deferred: list[Document] = []
    seen: dict[str, int] = {}
    for doc in documents:
        source = (doc.meta or {}).get("source", "unknown")
        if seen.get(source, 0) < max_per_source:
            seen[source] = seen.get(source, 0) + 1
            kept.append(doc)
        else:
            deferred.append(doc)
        if len(kept) == top_k:
            return kept
    return (kept + deferred)[:top_k]


def normalize_scores(documents: list[Document]) -> list[Document]:
    """Scores relative to the best result (1.0): fused scores are reciprocal-rank sums and read the same everywhere."""
    if not documents:
        return documents
    best = max((d.score or 0.0) for d in documents) or 1.0
    return [Document(id=d.id, content=d.content, meta=d.meta, score=(d.score or 0.0) / best) for d in documents]


# The factories below are what the tests replace, so no test downloads a model or calls an LLM.


def make_document_store(config: SecurityKbSearch) -> Any:
    """The collection the component searches."""
    return make_store(
        Settings.from_env(
            qdrant_url=config.qdrant_url, qdrant_index=config.qdrant_index, embedding_model=config.embedding_model
        )
    )


def make_text_embedder(config: SecurityKbSearch) -> Any:
    """The dense query encoder; its prefix must match the build's."""
    from haystack.utils import ComponentDevice
    from haystack_integrations.components.embedders.sentence_transformers import SentenceTransformersTextEmbedder

    return SentenceTransformersTextEmbedder(
        model=config.embedding_model,
        revision=config.embedding_revision,
        prefix=config.query_prefix,
        normalize_embeddings=True,
        device=ComponentDevice.from_str(config.device),
        local_files_only=config.offline,
        progress_bar=False,
    )


def make_sparse_text_embedder(config: SecurityKbSearch) -> Any:
    """The BM25 query encoder."""
    from haystack_integrations.components.embedders.fastembed import FastembedSparseTextEmbedder

    return FastembedSparseTextEmbedder(model=config.sparse_model, progress_bar=False)


def make_ranker(config: SecurityKbSearch) -> Any:
    """The cross-encoder, pinned through the Hugging Face loaders' kwargs (the ranker takes no `revision`)."""
    from haystack.utils import ComponentDevice
    from haystack_integrations.components.rankers.sentence_transformers import SentenceTransformersSimilarityRanker

    revision_kwargs: dict[str, Any] = {}
    if config.reranker_revision:
        pin = {"revision": config.reranker_revision}
        revision_kwargs = {"model_kwargs": pin, "tokenizer_kwargs": pin, "config_kwargs": pin}
    return SentenceTransformersSimilarityRanker(
        model=config.reranker_model,
        top_k=config.candidate_pool,
        scale_score=True,
        device=ComponentDevice.from_str(config.device),
        batch_size=16,
        **revision_kwargs,
    )


def make_llm(config: SecurityKbSearch) -> Any:
    """
    The sub-agent's chat generator.

    With `llm_base_url` (as in the agent files): an OpenAI-compatible server over chat/completions. Without it: OpenAI
    over the Responses API, with low reasoning effort.
    """
    from haystack.utils import Secret

    if config.llm_base_url:
        from haystack.components.generators.chat import OpenAIChatGenerator

        return OpenAIChatGenerator(
            model=config.llm_model,
            api_base_url=config.llm_base_url,
            api_key=Secret.from_env_var(config.llm_api_key_env),
            timeout=config.llm_timeout,
            max_retries=3,
            generation_kwargs={"max_tokens": config.max_output_tokens, **(config.llm_generation_kwargs or {})},
        )

    from haystack.components.generators.chat import OpenAIResponsesChatGenerator

    return OpenAIResponsesChatGenerator(
        model=config.llm_model,
        api_key=Secret.from_env_var(config.llm_api_key_env),
        timeout=config.llm_timeout,
        max_retries=3,
        generation_kwargs={"reasoning": {"effort": "low"}, "max_output_tokens": config.max_output_tokens},
    )


def download_models() -> None:
    """
    Download the retrieval models the agents' tool loads, at their pinned revisions, into the local caches.

    The sandbox image runs this when it is built (sandbox/security-triage/Dockerfile): the sandbox downloads nothing.
    """
    from security_agent.knowledge_base.sources import MODEL_REVISIONS

    tool = SecurityKbSearch(
        embedding_revision=MODEL_REVISIONS[DEFAULT_EMBEDDING_MODEL],
        reranker_revision=MODEL_REVISIONS[DEFAULT_RERANKER_MODEL],
    )
    for make in (make_text_embedder, make_sparse_text_embedder, make_ranker):
        make(tool).warm_up()


class _SubAgentTraces:
    """
    What the sub-agent did per query, for whoever measures the outer agent.

    The outer agent runs its tools in a thread pool, so neither thread-locals nor context variables lead back to the
    task that made a call: the sink is process-wide, matched by query text, and bounded.
    """

    def __init__(self, maxlen: int = 512) -> None:
        self._entries: collections.deque[dict] = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def record(self, entry: dict) -> None:
        """Add one lookup's trace."""
        with self._lock:
            self._entries.append(entry)

    def take(self, query: str) -> dict | None:
        """Remove and return the oldest trace for `query`, or None."""
        with self._lock:
            for i, entry in enumerate(self._entries):
                if entry.get("query") == query:
                    del self._entries[i]
                    return entry
        return None

    def clear(self) -> None:
        """Drop every trace."""
        with self._lock:
            self._entries.clear()


SUB_AGENT_TRACES = _SubAgentTraces()


@component
class SerializedTextEmbedder:
    """Holds the model lock across the wrapped dense embedder's `run`."""

    def __init__(self, embedder: Any) -> None:
        self.embedder = embedder

    def warm_up(self) -> None:
        """Warm up the wrapped embedder."""
        if hasattr(self.embedder, "warm_up"):
            self.embedder.warm_up()

    @component.output_types(embedding=list[float])
    def run(self, text: str) -> dict:
        """Embed `text`."""
        with _MODEL_LOCK:
            return {"embedding": self.embedder.run(text=text)["embedding"]}


@component
class SerializedSparseTextEmbedder:
    """Holds the model lock across the wrapped BM25 encoder's `run`."""

    def __init__(self, embedder: Any) -> None:
        self.embedder = embedder

    def warm_up(self) -> None:
        """Warm up the wrapped encoder."""
        if hasattr(self.embedder, "warm_up"):
            self.embedder.warm_up()

    @component.output_types(sparse_embedding=SparseEmbedding)
    def run(self, text: str) -> dict:
        """Encode `text`."""
        with _MODEL_LOCK:
            return {"sparse_embedding": self.embedder.run(text=text)["sparse_embedding"]}


@component
class SerializedRanker:
    """Holds the model lock across the wrapped cross-encoder's `run`."""

    def __init__(self, ranker: Any) -> None:
        self.ranker = ranker

    def warm_up(self) -> None:
        """Warm up the wrapped ranker."""
        if hasattr(self.ranker, "warm_up"):
            self.ranker.warm_up()

    @component.output_types(documents=list[Document])
    def run(self, query: str, documents: list[Document], top_k: int | None = None) -> dict:
        """Rank `documents` for `query`."""
        with _MODEL_LOCK:
            return {"documents": self.ranker.run(query=query, documents=documents, top_k=top_k)["documents"]}


@component
class KbResultShaper:
    """The retrieval pipeline's last step: fuse the two orderings, then cap per source."""

    def __init__(self, top_k: int = 5, max_per_source: int = 2, reranker_weight: float = 0.5) -> None:
        self.top_k = top_k
        self.max_per_source = max_per_source
        self.reranker_weight = reranker_weight

    @component.output_types(documents=list[Document])
    def run(self, retrieved: list[Document], reranked: list[Document] | None = None, top_k: int | None = None) -> dict:
        """The shaped result set."""
        top_k = top_k or self.top_k
        ordered = (
            retrieved if reranked is None else fuse_by_rank([retrieved, reranked], weights=[1.0, self.reranker_weight])
        )
        return {"documents": normalize_scores(cap_per_source(ordered, top_k, self.max_per_source))}


@component
class SecurityKbSearch:
    """
    Ask the knowledge base a question; returns one rendered string.

    Never raises from `run()` or `warm_up()`: a missing store, a model that will not load or a failed sub-agent run
    becomes a message in the tool result, so one misconfiguration cannot fail a whole task.
    """

    def __init__(  # noqa: PLR0913, PLR0917 - the agent files set each of these
        self,
        qdrant_url: str = DEFAULT_QDRANT_URL,
        qdrant_index: str = DEFAULT_QDRANT_INDEX,
        embedding_model: str = DEFAULT_EMBEDDING_MODEL,
        embedding_revision: str | None = None,
        query_prefix: str = DEFAULT_QUERY_PREFIX,
        sparse_model: str = DEFAULT_SPARSE_MODEL,
        reranker_model: str = DEFAULT_RERANKER_MODEL,
        reranker_revision: str | None = None,
        device: str = "cpu",
        top_k: int = 5,
        candidate_pool: int = 30,
        max_per_source: int = 2,
        reranker_weight: float = 0.5,
        max_output_chars: int = 12000,
        use_reranker: bool = True,
        offline: bool = False,
        llm_model: str = DEFAULT_LLM_MODEL,
        llm_base_url: str | None = None,
        llm_api_key_env: str = "OPENAI_API_KEY",
        llm_timeout: float = 120.0,
        max_output_tokens: int = 4000,
        llm_generation_kwargs: dict | None = None,
        max_agent_steps: int = 6,
        max_fetched_docs: int = 5,
    ) -> None:
        """
        Configure the tool; nothing is loaded until `warm_up()`.

        :param qdrant_url: Where Qdrant serves the collection.
        :param qdrant_index: The collection.
        :param embedding_model: The dense model; must be the one the collection was built with.
        :param embedding_revision: Its pinned revision on the Hugging Face Hub.
        :param query_prefix: The instruction prepended to queries (bge models are asymmetric).
        :param sparse_model: The BM25 encoder.
        :param reranker_model: The cross-encoder.
        :param reranker_revision: Its pinned revision.
        :param device: Where the models run.
        :param top_k: Results per search.
        :param candidate_pool: Candidates retrieved and reranked before shaping.
        :param max_per_source: At most this many results from one source; 0 turns the cap off.
        :param reranker_weight: The cross-encoder's weight in the fusion (retrieval has 1.0); 0 turns it off.
        :param max_output_chars: The size of the rendered tool result.
        :param use_reranker: Whether to rerank at all.
        :param offline: Load the models from the local cache only.
        :param llm_model: The sub-agent's model.
        :param llm_base_url: An OpenAI-compatible server for it; unset means OpenAI's Responses API.
        :param llm_api_key_env: The environment variable with its API key.
        :param llm_timeout: Seconds per call.
        :param max_output_tokens: Tokens per reply.
        :param llm_generation_kwargs: More request settings, for example thinking off.
        :param max_agent_steps: The sub-agent's step budget.
        :param max_fetched_docs: At most this many documents per `fetch_documents_by_filter` call.
        """
        self.qdrant_url = qdrant_url
        self.qdrant_index = qdrant_index
        self.embedding_model = embedding_model
        self.embedding_revision = embedding_revision
        self.query_prefix = query_prefix
        self.sparse_model = sparse_model
        self.reranker_model = reranker_model
        self.reranker_revision = reranker_revision
        self.device = device
        self.top_k = top_k
        self.candidate_pool = candidate_pool
        self.max_per_source = max_per_source
        self.reranker_weight = reranker_weight
        self.max_output_chars = max_output_chars
        self.use_reranker = use_reranker
        self.offline = offline
        self.llm_model = llm_model
        self.llm_base_url = llm_base_url
        self.llm_api_key_env = llm_api_key_env
        self.llm_timeout = llm_timeout
        self.max_output_tokens = max_output_tokens
        self.llm_generation_kwargs = llm_generation_kwargs
        self.max_agent_steps = max_agent_steps
        self.max_fetched_docs = max_fetched_docs
        self._pipeline: Any = None
        self._store: Any = None
        self._agent: Any = None
        self._error: str | None = None

    @property
    def error(self) -> str | None:
        """Why the tool is unavailable, or None."""
        return self._error

    @property
    def _retrieval_key(self) -> tuple:
        return (
            self.qdrant_url,
            self.qdrant_index,
            self.embedding_model,
            self.embedding_revision,
            self.query_prefix,
            self.sparse_model,
            self.reranker_model,
            self.reranker_revision,
            self.device,
            self.top_k,
            self.candidate_pool,
            self.max_per_source,
            self.reranker_weight,
            self.use_reranker,
            self.offline,
        )

    @property
    def _agent_key(self) -> tuple:
        return (
            *self._retrieval_key,
            self.llm_model,
            self.llm_timeout,
            self.max_output_tokens,
            json.dumps(self.llm_generation_kwargs, sort_keys=True) if self.llm_generation_kwargs else None,
            self.max_agent_steps,
            self.max_fetched_docs,
        )

    def _fail(self, error: str) -> None:
        self._error = error
        logger.warning("search_security_kb unavailable: %s", error)

    def warm_up_retrieval(self) -> None:
        """Connect to the collection and load the models, without the sub-agent. Records failures instead of raising."""
        if self._pipeline is not None or self._error is not None:
            return
        key = self._retrieval_key
        with _CACHE_LOCK:
            cached = _PIPELINES.get(key)
        if cached is not None:
            self._pipeline, self._store = cached
            return
        try:
            store = make_document_store(self)
            check_model(
                read_meta(store, Settings.from_env(qdrant_url=self.qdrant_url, qdrant_index=self.qdrant_index)),
                self.embedding_model,
            )
            pipeline = self._build_retrieval_pipeline(store)
        except KbStoreError as exc:
            self._fail(str(exc))
            return
        except Exception as exc:
            self._fail(
                f"Security knowledge-base search is unavailable: could not load the retrieval models "
                f"({type(exc).__name__}: {exc}). The embedding model {self.embedding_model!r} and the reranker "
                f"{self.reranker_model!r} are downloaded from Hugging Face on first use; offline, pre-fill HF_HOME and "
                f"set KB_OFFLINE=1."
            )
            return
        with _CACHE_LOCK:
            _PIPELINES.setdefault(key, (pipeline, store))
            self._pipeline, self._store = _PIPELINES[key]

    def warm_up(self) -> None:
        """Connect, load the models, build the sub-agent. Never raises: that would fail the outer agent's warm-up."""
        if self._agent is not None or self._error is not None:
            return
        self.warm_up_retrieval()
        if self._error is not None:
            return
        key = self._agent_key
        with _CACHE_LOCK:
            cached = _AGENTS.get(key)
        if cached is not None:
            self._agent = cached
            return
        try:
            agent = self._build_agent()
        except Exception as exc:
            self._fail(
                f"Security knowledge-base search is unavailable: could not build the retrieval agent "
                f"({type(exc).__name__}: {exc})."
            )
            return
        with _CACHE_LOCK:
            _AGENTS.setdefault(key, agent)
            self._agent = _AGENTS[key]

    def _input_mapping(self) -> dict[str, list[str]]:
        """How the pack's `search_documents` inputs (`query`, `filters`) reach the retrieval pipeline."""
        query_sockets = ["dense_embedder.text", "sparse_embedder.text"]
        if self.use_reranker:
            query_sockets.append("ranker.query")
        return {"query": query_sockets, "filters": ["retriever.filters"]}

    def _build_retrieval_pipeline(self, store: Any) -> Any:
        """Hybrid retrieval in one request (Qdrant fuses both vectors), the rerank, the shaper."""
        from haystack import Pipeline
        from haystack_integrations.components.retrievers.qdrant import QdrantHybridRetriever

        pipeline = Pipeline()
        pipeline.add_component("dense_embedder", SerializedTextEmbedder(make_text_embedder(self)))
        pipeline.add_component("sparse_embedder", SerializedSparseTextEmbedder(make_sparse_text_embedder(self)))
        pipeline.add_component("retriever", QdrantHybridRetriever(document_store=store, top_k=self.candidate_pool))
        pipeline.add_component(
            "shaper",
            KbResultShaper(top_k=self.top_k, max_per_source=self.max_per_source, reranker_weight=self.reranker_weight),
        )
        pipeline.connect("dense_embedder.embedding", "retriever.query_embedding")
        pipeline.connect("sparse_embedder.sparse_embedding", "retriever.query_sparse_embedding")
        pipeline.connect("retriever.documents", "shaper.retrieved")
        if self.use_reranker:
            # The whole pool: the shaper fuses this ordering with the retrieval ordering.
            pipeline.add_component("ranker", SerializedRanker(make_ranker(self)))
            pipeline.connect("retriever.documents", "ranker.documents")
            pipeline.connect("ranker.documents", "shaper.reranked")
        pipeline.warm_up()
        return pipeline

    def _build_agent(self) -> Any:
        """Hand the warm store and retrieval pipeline to the agent pack."""
        from haystack_integrations.agent_pack.advanced_rag import create_advanced_rag_agent

        agent = create_advanced_rag_agent(
            document_store=self._store,
            retriever=self._pipeline,
            retrieval_pipeline_input_mapping=self._input_mapping(),
            retrieval_pipeline_output_mapping={"shaper.documents": "documents"},
            llm=make_llm(self),
            backup_answer_llm=make_llm(self),
            system_prompt=prompts.KB_AGENT_SYSTEM_PROMPT,
            max_agent_steps=self.max_agent_steps,
            max_fetched_docs=self.max_fetched_docs,
            # A tool error the sub-agent can read and retry beats an exception that costs the whole lookup.
            raise_on_tool_invocation_failure=False,
        )
        agent.warm_up()
        return agent

    @component.output_types(results=str)
    def run(self, query: str) -> dict:
        """
        Ask the knowledge base a question.

        :param query: What to look up: a natural-language question about a weakness class, a technique or a CVE, or an
            exact identifier such as `CVE-2024-21626` or `CWE-787`.
        :returns: `results`, the rendered briefing or a message saying why there is none.
        """
        from security_agent.primevul.agent import openai_messages, usage

        self.warm_up()
        if self._error is not None:
            return {"results": self._error}
        query = (query or "").strip()
        if not query:
            return {"results": "No question given. Ask about a weakness, a technique or a CVE."}
        t0 = time.monotonic()
        try:
            result = self._agent.run(messages=[ChatMessage.from_user(query)])
        except Exception as exc:  # a tool result must stay a string
            logger.exception("search_security_kb failed for query %r", query)
            SUB_AGENT_TRACES.record(
                {"query": query, "error": f"{type(exc).__name__}: {exc}", "seconds": round(time.monotonic() - t0, 1)}
            )
            return {
                "results": f"Security knowledge-base lookup failed ({type(exc).__name__}: {exc}). The knowledge base "
                f"may need rebuilding: `hatch run primevul:kb build`."
            }
        answer = (result["last_message"].text or "").strip()
        documents = result.get("documents") or []
        SUB_AGENT_TRACES.record(
            {
                "query": query,
                "messages": openai_messages(result.get("messages")),
                "steps": result.get("step_count"),
                "documents": len(documents),
                "answer": answer[:400],
                "usage": usage(result.get("messages")),
                "seconds": round(time.monotonic() - t0, 1),
            }
        )
        if not answer:
            return {
                "results": f"The knowledge-base lookup for {query!r} produced no answer. Try a broader phrasing (the "
                f"weakness class rather than an exact function name)."
            }
        return {
            "results": render.render_answer(
                answer, documents, query=query, max_output_chars=self.max_output_chars, steps=result.get("step_count")
            )
        }

    def retrieve(self, query: str, filters: dict | None = None, top_k: int | None = None) -> list[Document]:
        """The retrieval pipeline alone, with no LLM (`kb query`)."""
        self.warm_up_retrieval()
        if self._error is not None:
            raise KbStoreError(self._error)
        top_k = top_k or self.top_k
        pool = max(top_k * 6, self.candidate_pool)
        inputs: dict[str, dict[str, Any]] = {
            "dense_embedder": {"text": query},
            "sparse_embedder": {"text": query},
            "retriever": {"filters": filters, "top_k": pool},
            "shaper": {"top_k": top_k},
        }
        if self.use_reranker:
            inputs["ranker"] = {"query": query, "top_k": pool}
        return self._pipeline.run(inputs)["shaper"]["documents"]

    def to_dict(self) -> dict:
        """Serialize the component."""
        return default_to_dict(
            self,
            qdrant_url=self.qdrant_url,
            qdrant_index=self.qdrant_index,
            embedding_model=self.embedding_model,
            embedding_revision=self.embedding_revision,
            query_prefix=self.query_prefix,
            sparse_model=self.sparse_model,
            reranker_model=self.reranker_model,
            reranker_revision=self.reranker_revision,
            device=self.device,
            top_k=self.top_k,
            candidate_pool=self.candidate_pool,
            max_per_source=self.max_per_source,
            reranker_weight=self.reranker_weight,
            max_output_chars=self.max_output_chars,
            use_reranker=self.use_reranker,
            offline=self.offline,
            llm_model=self.llm_model,
            llm_base_url=self.llm_base_url,
            llm_api_key_env=self.llm_api_key_env,
            llm_timeout=self.llm_timeout,
            max_output_tokens=self.max_output_tokens,
            llm_generation_kwargs=self.llm_generation_kwargs,
            max_agent_steps=self.max_agent_steps,
            max_fetched_docs=self.max_fetched_docs,
        )

    @classmethod
    def from_dict(cls, data: dict) -> SecurityKbSearch:
        """Deserialize the component."""
        return default_from_dict(cls, data)
