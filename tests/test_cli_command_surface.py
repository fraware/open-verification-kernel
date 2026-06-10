from scripts.check_command_surface import main as check_command_surface


def test_release_metadata_commands_have_cli_implementations() -> None:
    assert check_command_surface() == 0
