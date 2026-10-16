from haystack.dataclasses import Document

from haystack_integrations.components.prompt_assembler import PromptAssembler


def test_renders_context():
    prompt = PromptAssembler().run(
        question="What changed?", documents=[Document(content="the config")]
    )["prompt"]
    assert "the config" in prompt
    assert "What changed?" in prompt
