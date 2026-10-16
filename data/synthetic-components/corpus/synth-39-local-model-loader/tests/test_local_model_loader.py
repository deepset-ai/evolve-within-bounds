import pytest

from haystack_integrations.components.local_model_loader import LocalModelLoader
from haystack_integrations.components.local_model_loader.local_model_loader_component import (
    ModelRejected,
    resolve_model_path,
)


def test_resolves_local_model(tmp_path):
    (tmp_path / "reranker-small").mkdir()
    assert resolve_model_path(tmp_path, "reranker-small").name == "reranker-small"


def test_escaping_identifier_rejected(tmp_path):
    with pytest.raises(ModelRejected):
        resolve_model_path(tmp_path, "../../etc")
