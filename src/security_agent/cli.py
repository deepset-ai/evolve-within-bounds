# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The `security-agent` command line: one command group per benchmark.

  security-agent synthetic ...   the synthetic custom-component benchmark (`security_agent.synthetic.cli`)
"""

from __future__ import annotations

import argparse
import sys

from security_agent import __version__


def build_parser() -> argparse.ArgumentParser:
    """All commands."""
    from security_agent.synthetic import cli as synthetic

    parser = argparse.ArgumentParser(prog="security-agent")
    parser.add_argument("--version", action="version", version=__version__)
    groups = parser.add_subparsers(dest="benchmark", required=True)
    synthetic.add_commands(groups.add_parser("synthetic", help="the synthetic custom-component benchmark"))
    return parser


def main(argv: list[str] | None = None) -> None:
    """Run one command; errors the commands expect end with a message and exit code 2."""
    from security_agent.synthetic import cli as synthetic

    args = build_parser().parse_args(argv)
    expected: tuple[type[Exception], ...] = (*synthetic.errors(), ValueError)
    try:
        code = args.handler(args)
    except expected as exc:
        print(f"error: {exc}", file=sys.stderr)
        code = 2
    raise SystemExit(code)


if __name__ == "__main__":
    main()
