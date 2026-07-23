"""Resolve the immutable commit that produced verification metrics.

Badge and summary commits may use ``[skip ci]`` and must not be confused with
the commit that actually ran FormalPR-Bench / pilot metrics. Prefer an explicit
override, then GitHub Actions SHA, then local ``git rev-parse HEAD``.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def resolve_verified_source_sha(
    *,
    explicit: str | None = None,
    repo_root: Path | None = None,
) -> str | None:
    """Return a full git commit SHA for metric provenance, or None if unknown."""
    if explicit:
        value = explicit.strip()
        return value or None
    for key in ("OVK_VERIFIED_SOURCE_SHA", "GITHUB_SHA"):
        value = (os.environ.get(key) or "").strip()
        if value:
            return value
    root = repo_root or Path(__file__).resolve().parents[1]
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None
