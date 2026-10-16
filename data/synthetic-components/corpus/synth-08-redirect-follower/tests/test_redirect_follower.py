import pytest

from custom_components.redirect_follower import RedirectFollower
from custom_components.redirect_follower.redirect_follower import RedirectError


def test_allowed_host_passes():
    follower = RedirectFollower()
    assert follower.check_host("https://docs.example.invalid/a").endswith("/a")


def test_foreign_host_rejected():
    with pytest.raises(RedirectError):
        RedirectFollower().check_host("https://elsewhere.example.invalid/a")
