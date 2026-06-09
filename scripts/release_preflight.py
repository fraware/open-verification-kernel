#!/usr/bin/env python
"""Run OVK local release preflight checks."""

from __future__ import annotations

from scripts.check_command_surface import main as check_command_surface
from scripts.check_release_metadata import main as check_release_metadata
from scripts.smoke_release_local import run_local_release_smoke


def main() -> int:
    failures: list[str] = []
    if check_release_metadata() != 0:
        failures.append("release metadata preflight failed")
    if check_command_surface() != 0:
        failures.append("command surface preflight failed")
    failures.extend(run_local_release_smoke())

    for failure in failures:
        print(failure)
    if failures:
        return 1
    print("OVK release preflight checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
