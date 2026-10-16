from __future__ import annotations

import pytest

from haystack_component_vulnerability_benchmark.cli import build_parser


@pytest.mark.parametrize(
    "argv",
    [
        ["inventory", "--check-access"],
        ["materialize", "--output", "x", "--offline"],
        ["materialize", "--output", "x", "--cache", "y"],
        ["materialize", "--output", "x", "--private-map", "y"],
        ["validate", "--with-cache"],
        ["validate", "--cache", "y"],
    ],
)
def test_removed_flags_are_rejected(argv: list[str]) -> None:
    """The git-and-network era flags must be gone, not merely ignored."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(argv)


def test_current_flags_are_accepted() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["materialize", "--output", "out", "--answer-key", "key.json", "--no-verify-corpus"]
    )
    assert args.verify_corpus is False
    assert args.command == "materialize"
    assert parser.parse_args(["score", "p.jsonl", "--line-tolerance", "0"]).line_tolerance == 0
