#!/usr/bin/env python
"""Run OVK release preflight checks with a structured report."""

from __future__ import annotations

import argparse
from pathlib import Path

from ovk.core.json_io import write_json_file
from ovk.core.preflight import PreflightReport, check_from_exit_code, check_from_failures
from scripts.check_command_surface import main as check_command_surface
from scripts.check_release_metadata import main as check_release_metadata
from scripts.smoke_release_local import run_local_release_smoke


def build_release_preflight_report() -> PreflightReport:
    """Run release preflight checks and return a structured report."""
    return PreflightReport(
        (
            check_from_exit_code("release_metadata", check_release_metadata(), "release metadata preflight failed"),
            check_from_exit_code("command_surface", check_command_surface(), "command surface preflight failed"),
            check_from_failures("local_release_smoke", run_local_release_smoke()),
        )
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run OVK structured release preflight checks")
    parser.add_argument("--output", type=Path, default=None, help="Optional JSON preflight report output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_release_preflight_report()
    if args.output is not None:
        write_json_file(args.output, report.to_dict())
    for failure in report.failures:
        print(failure)
    if not report.passed:
        return 1
    print("OVK structured release preflight checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
