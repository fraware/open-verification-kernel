#!/usr/bin/env python
"""Copy repo resource trees into ovk/package_data for wheel builds."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "ovk" / "package_data"
RESOURCE_DIRS = ("schemas", "templates", "adapters", "examples", "benchmarks", "scripts")


def sync_package_data(*, clean: bool = True) -> Path:
    """Mirror resource directories required at runtime into the Python package."""
    if clean and TARGET.exists():
        shutil.rmtree(TARGET)
    TARGET.mkdir(parents=True, exist_ok=True)
    for name in RESOURCE_DIRS:
        source = ROOT / name
        if not source.exists():
            continue
        destination = TARGET / name
        shutil.copytree(source, destination)
    action_yml = ROOT / "action.yml"
    if action_yml.exists():
        shutil.copy2(action_yml, TARGET / "action.yml")
    return TARGET


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync OVK package data for PyPI wheels")
    parser.add_argument("--no-clean", action="store_true", help="Merge into existing package_data/")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    destination = sync_package_data(clean=not args.no_clean)
    print(f"Synced package data to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
