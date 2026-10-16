from haystack_integrations.components.error_reporter import ErrorReporter
from haystack_integrations.components.error_reporter.error_reporter_component import scrub


def test_newlines_are_flattened():
    assert "\n" not in scrub("line\nINFO forged entry")


def test_token_shaped_value_is_redacted():
    assert "[redacted]" in scrub("Bearer abcdefghijklmnopqrstuvwxyz012345")


def test_long_value_is_clipped():
    assert len(scrub("x" * 5000)) < 400
