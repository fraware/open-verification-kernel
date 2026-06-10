#!/usr/bin/env python
"""Check that release metadata commands are implemented by the CLI."""

from __future__ import annotations

from ovk.cli import app
from ovk.core.release_metadata import SUPPORTED_COMMANDS


def _command_name(command) -> str:
    return command.name or ""


def _registered_command_names(typer_app=app, prefix: str = "") -> set[str]:
    names: set[str] = set()
    for command in typer_app.registered_commands:
        if command.name:
            key = f"{prefix}{command.name}".strip()
            names.add(key)
    for group in getattr(typer_app, "registered_groups", []):
        group_name = str(getattr(group, "name", "") or "")
        child_prefix = f"{prefix}{group_name} ".strip()
        if child_prefix:
            child_prefix = f"{child_prefix} "
        names.update(_registered_command_names(group.typer_instance, child_prefix))
    return names


def _metadata_command_to_cli_name(command: str) -> str:
    return command.removeprefix("ovk ").replace("_", "-")


def main() -> int:
    registered = _registered_command_names()
    failures: list[str] = []
    for command in SUPPORTED_COMMANDS:
        cli_name = _metadata_command_to_cli_name(command)
        if cli_name not in registered:
            failures.append(f"missing CLI implementation for {command} (expected Typer command {cli_name})")
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print("OVK command surface is consistent with release metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
