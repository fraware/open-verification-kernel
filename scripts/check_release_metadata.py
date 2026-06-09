#!/usr/bin/env python
"""Check OVK release metadata consistency."""

from __future__ import annotations

from pathlib import Path

import ovk
from ovk.core.release_metadata import OVK_RELEASE_CANDIDATE, release_metadata


def main() -> int:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    expected = OVK_RELEASE_CANDIDATE
    failures: list[str] = []
    if f'version = "{expected}"' not in pyproject:
        failures.append("pyproject version does not match release metadata")
    if ovk.__version__ != expected:
        failures.append("package __version__ does not match release metadata")
    metadata = release_metadata()
    if metadata["release_candidate"] != expected:
        failures.append("release metadata payload does not match release constant")
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print(f"OVK release metadata is consistent: {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
