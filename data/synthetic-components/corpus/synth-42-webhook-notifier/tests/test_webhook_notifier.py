import pytest

from custom_components.webhook_notifier import WebhookNotifier
from custom_components.webhook_notifier.webhook_notifier_component import WebhookError, check_target

ALLOWED = {"hooks.example.invalid"}


def test_https_host_accepted():
    assert check_target("https://hooks.example.invalid/runs", ALLOWED).endswith("/runs")


def test_plain_http_rejected():
    with pytest.raises(WebhookError):
        check_target("http://hooks.example.invalid/runs", ALLOWED)


def test_allowed_host_is_enforced_at_construction():
    with pytest.raises(WebhookError):
        WebhookNotifier(url="https://elsewhere.example.invalid/runs")
