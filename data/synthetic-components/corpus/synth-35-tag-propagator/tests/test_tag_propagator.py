from haystack.dataclasses import Document

from haystack_integrations.components.tag_propagator import TagPropagator


def test_split_keeps_its_own_value():
    parent = Document(id="p1", content="x", meta={"topics": ["a"]})
    split = Document(id="s1", content="y", meta={"parent_id": "p1", "topics": ["own"]})
    out = TagPropagator().run(parents=[parent], splits=[split])
    assert out["documents"][0].meta["topics"] == ["own"]


def test_split_without_parent_is_unchanged():
    split = Document(id="s1", content="y", meta={"parent_id": "missing"})
    out = TagPropagator().run(parents=[], splits=[split])
    assert out["documents"][0].meta == {"parent_id": "missing"}
