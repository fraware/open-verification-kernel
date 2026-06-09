from pathlib import Path

from ovk.core.release_metadata import SUPPORTED_COMMANDS


def test_release_metadata_commands_have_cli_implementations() -> None:
    cli_source = Path("ovk/cli.py").read_text(encoding="utf-8")
    command_to_function = {
        "ovk init": "def init(",
        "ovk ci": "def ci(",
        "ovk auth-obligation": "def auth_obligation(",
        "ovk infra-exposure": "def infra_exposure(",
    }
    for command in SUPPORTED_COMMANDS:
        assert command_to_function[command] in cli_source
