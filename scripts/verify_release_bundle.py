#!/usr/bin/env python
"""Verify an OVK release bundle directory."""

from __future__ import annotations

import argparse
from pathlib import Path

from ovk.core.release_bundle import verify_release_bundle


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify OVK release bundle artifacts")
    parser.add_argument("bundle_dir", type=Path, help="Release bundle directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    failures = verify_release_bundle(args.bundle_dir)
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print("OVK release bundle verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
