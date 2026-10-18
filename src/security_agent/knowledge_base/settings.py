# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
How the knowledge base is built and where it lives.

The query side (`search.SecurityKbSearch`) carries its own copies of these values as init parameters, so an agent file
says exactly what it searches. The two must agree on the embedding model and its query prefix, and `store.check_model`
refuses a collection built with another model.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class Settings:
    """The knowledge base's settings. `from_env` applies the environment's overrides."""

    qdrant_url: str = "http://localhost:6333"
    qdrant_index: str = "security_kb"
    qdrant_timeout: float = 60.0
    # The dense vector. Changing the model invalidates every stored vector.
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    embedding_dim: int = 384
    # bge models are asymmetric: the instruction goes on the query side only.
    query_prefix: str = "Represent this sentence for searching relevant passages: "
    passage_prefix: str = ""
    # The lexical leg: BM25 as a sparse vector.
    sparse_model: str = "Qdrant/bm25"
    reranker_model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"
    # "cpu", never None: left to choose, sentence-transformers picks MPS on macOS, and the same text would embed
    # differently on the machine that built the store and the one that queries it.
    device: str = "cpu"
    st_batch_size: int = 64
    offline: bool = False
    # Where downloaded sources are kept, so a rebuild downloads nothing.
    cache_dir: Path = field(default_factory=lambda: REPO_ROOT / "work" / "knowledge-base")

    @classmethod
    def from_env(cls, **overrides: Any) -> Settings:
        """The defaults, then KB_QDRANT_URL, KB_QDRANT_INDEX, KB_DEVICE and KB_OFFLINE, then `overrides`."""
        settings = cls()
        env: dict[str, Any] = {}
        if os.environ.get("KB_QDRANT_URL"):
            env["qdrant_url"] = os.environ["KB_QDRANT_URL"].strip()
        if os.environ.get("KB_QDRANT_INDEX"):
            env["qdrant_index"] = os.environ["KB_QDRANT_INDEX"].strip()
        if os.environ.get("KB_DEVICE"):
            env["device"] = os.environ["KB_DEVICE"].strip()
        if os.environ.get("KB_OFFLINE"):
            env["offline"] = os.environ["KB_OFFLINE"].strip().lower() in {"1", "true", "yes", "on"}
        env.update({k: v for k, v in overrides.items() if v is not None})
        return replace(settings, **env)
