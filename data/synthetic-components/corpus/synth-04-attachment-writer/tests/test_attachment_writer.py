import pytest
from haystack.dataclasses import Document

from custom_components.attachment_writer import AttachmentWriter
from custom_components.attachment_writer.staging_paths import StagingError, contained_path


def test_writes_under_root(tmp_path):
    writer = AttachmentWriter(staging_root=str(tmp_path))
    document = Document(content="body", meta={"attachment_name": "reports/a.txt"})
    assert writer.run(documents=[document])["written"] == ["reports/a.txt"]
    assert (tmp_path / "reports/a.txt").read_text() == "body"


def test_escaping_name_is_rejected(tmp_path):
    with pytest.raises(StagingError):
        contained_path(tmp_path, "../../etc/passwd")
