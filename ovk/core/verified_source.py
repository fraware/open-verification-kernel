"""Resolve benchmark vs verified source SHAs for metric provenance.

``benchmark_source_sha`` is the commit whose FormalPR-Bench (or badge) artifacts
were measured. ``verified_source_sha`` is only set when a complete observed
required-workflow set is attested (explicit override or ``OVK_VERIFIED_SOURCE_SHA``).

Badge-only / ``[skip ci]`` commits must never be labeled verified merely because
``GITHUB_SHA`` or ``git HEAD`` is available.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _git_head(repo_root: Path | None) -> str | None:
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


def resolve_benchmark_source_sha(
    *,
    explicit: str | None = None,
    repo_root: Path | None = None,
) -> str | None:
    """Return the commit SHA that produced benchmark/badge artifacts, if known."""
    if explicit:
        value = explicit.strip()
        return value or None
    for key in ("OVK_BENCHMARK_SOURCE_SHA", "GITHUB_SHA"):
        value = (os.environ.get(key) or "").strip()
        if value:
            return value
    return _git_head(repo_root)


def resolve_verified_source_sha(
    *,
    explicit: str | None = None,
    repo_root: Path | None = None,
) -> str | None:
    """Return a verified-source SHA only when explicitly attested.

    Does not fall back to ``GITHUB_SHA`` or ``git HEAD``. Those identify the
    current checkout / workflow run and belong on ``benchmark_source_sha`` unless
    maintainers also set ``OVK_VERIFIED_SOURCE_SHA`` after observing the full
    required-workflow set.
    """
    del repo_root  # retained for API compatibility; verified SHA is never inferred from HEAD
    if explicit:
        value = explicit.strip()
        return value or None
    value = (os.environ.get("OVK_VERIFIED_SOURCE_SHA") or "").strip()
    return value or None
