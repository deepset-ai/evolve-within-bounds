import pytest

from custom_components.control_plane_client.identifiers import (
    IdentifierError,
    check_resource,
    check_workspace,
)


def test_valid_names():
    assert check_workspace("team-a") == "team-a"
    assert check_resource("indexing-job-1") == "indexing-job-1"


@pytest.mark.parametrize("name", ["../admin", "Team A", ""])
def test_invalid_workspace(name):
    with pytest.raises(IdentifierError):
        check_workspace(name)
