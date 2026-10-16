import json

from haystack.dataclasses import Document

from haystack_integrations.components.metadata_enricher import MetadataEnricher
from haystack_integrations.components.metadata_enricher.merge_policy import writable_subset
from haystack_integrations.components.metadata_enricher.prompt_source import render_prompt


class FakeGenerator:
    def __init__(self, payload):
        self.payload = payload
        self.prompts = []

    def run(self, prompt):
        self.prompts.append(prompt)
        return {"replies": [json.dumps(self.payload)]}


def test_allowed_keys_are_merged():
    assert writable_subset({"summary": "s", "topics": ["a"]}) == {"summary": "s", "topics": ["a"]}
def test_document_text_is_data_not_template():
    prompt = render_prompt("{{ 7 * 7 }}")
    assert "{{ 7 * 7 }}" in prompt
    assert "49" not in prompt
