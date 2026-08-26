#!/usr/bin/env python
"""Check OVK release metadata and public status consistency."""

from __future__ import annotations

from pathlib import Path

import ovk
from ovk.core.project_status import check_committed_status_truthfulness
from ovk.core.release_metadata import OVK_RELEASE_CANDIDATE, release_metadata


def main() -> int:
    repo_root = Path(".")
    pyproject = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    expected = OVK_RELEASE_CANDIDATE
    failures: list[str] = []
    if f'version = "{expected}"' not in pyproject:
        failures.append("pyproject version does not match release metadata")
    if ovk.__version__ != expected:
        failures.append("package __version__ does not match release metadata")
    metadata = release_metadata()
    if metadata["release_candidate"] != expected:
        failures.append("release metadata payload does not match release constant")

    # STATUS.md is a public release-claim surface. A stale maturity snapshot is
    # therefore a release-metadata failure, not merely a documentation issue.
    failures.extend(check_committed_status_truthfulness(repo_root))

    for failure in failures:
        print(failure)
    if failures:
        return 1
    print(f"OVK release metadata and public status are consistent: {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
