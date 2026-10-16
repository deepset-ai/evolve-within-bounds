import pytest

from custom_components.doc_export_runner import DocExportRunner
from custom_components.doc_export_runner.converter_binary import ConverterMissing, resolve_binary


def test_absolute_path_accepted():
    assert resolve_binary("/bin/sh") == "/bin/sh"


def test_relative_path_rejected():
    with pytest.raises(ConverterMissing):
        resolve_binary("./doc-convert")


def test_unknown_binary_rejected():
    with pytest.raises(ConverterMissing):
        resolve_binary("definitely-not-installed-converter")


def test_licence_travels_in_the_environment(monkeypatch):
    monkeypatch.setenv("BENCHMARK_INERT_TOKEN_EXPORT", "inert-value")
    environment = DocExportRunner()._environment()
    assert environment["DOC_CONVERT_LICENCE"] == "inert-value"
