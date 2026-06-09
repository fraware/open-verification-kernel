# Sprint 6 Command Surface Update

Sprint 6 now includes command-surface consistency coverage.

Implemented:

- Added `tests/test_cli_command_surface.py`.
- Added `scripts/check_command_surface.py`.
- The test checks that release metadata commands have corresponding CLI implementations.
- The script gives maintainers a runnable pre-release command-surface check.

Blocked:

- A direct pytest wrapper for `scripts/check_command_surface.py` was blocked by connector controls.

This helps keep release notes, tagging checks, and the actual CLI command surface aligned.
