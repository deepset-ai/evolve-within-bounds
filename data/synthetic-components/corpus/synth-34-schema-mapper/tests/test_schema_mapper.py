import pytest
from haystack.dataclasses import Document

from haystack_integrations.components.schema_mapper import SchemaMapper
from haystack_integrations.components.schema_mapper.schema_mapper_component import (
    MappingError,
    check_mapping,
)


def test_maps_field():
    mapper = SchemaMapper(mapping={"headline": "title"})
    out = mapper.run(documents=[Document(content="x", meta={"headline": "H"})])
    assert out["documents"][0].meta["title"] == "H"
