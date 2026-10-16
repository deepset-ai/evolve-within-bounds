import pytest

from custom_components.csv_frame_loader import CsvFrameLoader
from custom_components.csv_frame_loader.source_policy import SourceRejected, local_source


def test_reads_local_file(tmp_path):
    (tmp_path / "orders.csv").write_text("id,total\n1,99\n")
    rows = CsvFrameLoader(data_root=str(tmp_path)).run(reference="orders.csv")["rows"]
    assert rows == [{"id": "1", "total": "99"}]


def test_remote_reference_rejected(tmp_path):
    with pytest.raises(SourceRejected):
        local_source(tmp_path, "https://elsewhere.example.invalid/a.csv")


def test_escaping_reference_rejected(tmp_path):
    with pytest.raises(SourceRejected):
        local_source(tmp_path, "../../etc/passwd")
