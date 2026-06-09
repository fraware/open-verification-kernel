#!/usr/bin/env python
"""Check that release metadata commands are implemented by the CLI."""

from __future__ import annotations

from pathlib import Path

from ovk.core.release_metadata import SUPPORTED_COMMANDS


COMMAND_TO_FUNCTION = {
    "ovk init": "def init(",
    "ovk ci": "def ci(",
    "ovk auth-obligation": "def auth_obligation(",
    "ovk infra-exposure": "def infra_exposure(",
}


def main() -> int:
    cli_source = Path("ovk/cli.py").read_text(encoding="utf-8")
    failures: list[str] = []
    for command in SUPPORTED_COMMANDS:
        expected = COMMAND_TO_FUNCTION.get(command)
        if expected is None:
            failures.append(f"missing command mapping: {command}")
            continue
        if expected not in cli_source:
            failures.append(f"missing CLI implementation for {command}")
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print("OVK command surface is consistent with release metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
