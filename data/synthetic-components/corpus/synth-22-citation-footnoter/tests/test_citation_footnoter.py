from haystack.dataclasses import Document

from custom_components.citation_footnoter import CitationFootnoter
def test_no_documents_passes_through():
    assert CitationFootnoter().run(answer="A", documents=[])["answer"] == "A"
