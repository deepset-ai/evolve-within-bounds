# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
The `security-agent` command line: one command group per benchmark.

  security-agent synthetic ...   the synthetic custom-component benchmark (`security_agent.synthetic.cli`)
  security-agent primevul ...    PrimeVul (`security_agent.primevul.cli`)

Each group needs its extra (`pip install '.[synthetic]'`, `'.[primevul]'`); a group whose extra is missing says so.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from types import ModuleType

from security_agent import __version__

GROUPS = {
    "synthetic": ("security_agent.synthetic.cli", "the synthetic custom-component benchmark"),
    "primevul": ("security_agent.primevul.cli", "PrimeVul"),
}


def _group(name: str) -> ModuleType | None:
    """A command group's module, or None when its extra is not installed."""
    try:
        return importlib.import_module(GROUPS[name][0])
    except ImportError:
        return None


def build_parser() -> argparse.ArgumentParser:
    """All commands."""
    parser = argparse.ArgumentParser(prog="security-agent")
    parser.add_argument("--version", action="version", version=__version__)
    groups = parser.add_subparsers(dest="group", required=True)
    for name, (_, help_text) in GROUPS.items():
        group_parser = groups.add_parser(name, help=help_text)
        module = _group(name)
        if module is None:
            group_parser.add_argument("rest", nargs=argparse.REMAINDER)
            group_parser.set_defaults(handler=lambda _args, extra=name: _missing(extra))
        else:
            module.add_commands(group_parser)
    return parser


def _missing(extra: str) -> int:
    print(f"error: install the {extra!r} extra for these commands (hatch run {extra}:..., or pip install '.[{extra}]')")
    return 2


def main(argv: list[str] | None = None) -> None:
    """Run one command; errors the commands expect end with a message and exit code 2."""
    args = build_parser().parse_args(argv)
    module = _group(args.group)
    expected: tuple[type[Exception], ...] = (*(module.errors() if module else ()), ValueError)
    try:
        code = args.handler(args)
    except expected as exc:
        print(f"error: {exc}", file=sys.stderr)
        code = 2
    raise SystemExit(code)


if __name__ == "__main__":
    main()
