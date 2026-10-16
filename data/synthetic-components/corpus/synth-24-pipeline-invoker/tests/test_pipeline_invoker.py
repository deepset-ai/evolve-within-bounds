from custom_components.pipeline_invoker import PipelineInvoker


def test_valid_name():
    assert PipelineInvoker(pipeline="search-v2").pipeline == "search-v2"


def test_defaults():
    invoker = PipelineInvoker()
    assert invoker.base_url.endswith("/api/v1")
    assert invoker.timeout == 30.0
