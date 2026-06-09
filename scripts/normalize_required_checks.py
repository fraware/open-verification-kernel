#!/usr/bin/env python
"""Normalize required-check metadata for OVK.

Input may be either explicit required-check metadata or a saved branch-protection
JSON response. Output is the canonical OVK shape used by `ovk ci`.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ovk.core.check_metadata import normalize_required_check_metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize OVK required-check metadata")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, default=Path("ovk-required-checks.json"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data = json.loads(args.input.read_text(encoding="utf-8"))
    normalized = normalize_required_check_metadata(data)
    payload = {key: value for key, value in normalized.items() if value is not None}
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
