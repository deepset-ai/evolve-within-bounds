import json

import pytest
from haystack.dataclasses import Document

from custom_components.sidecar_reader import SidecarReader
from custom_components.sidecar_reader.sidecar_reader import SidecarError


def test_merges_sidecar(tmp_path):
    (tmp_path / "doc.meta.json").write_text(json.dumps({"lang": "en"}))
    reader = SidecarReader(ingest_root=str(tmp_path))
    out = reader.run(documents=[Document(content="x", meta={"source_name": "doc"})])
    assert out["documents"][0].meta["lang"] == "en"
