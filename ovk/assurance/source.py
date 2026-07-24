"""Source commit and producer metadata helpers for PCS exports."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from ovk.assurance.errors import AssuranceError
from ovk.core.release_metadata import OVK_VERSION
from ovk.paths import ovk_data_root

PRODUCER_NAME = "OVK"
DEFAULT_SOURCE_REPO = "https://github.com/fraware/open-verification-kernel"

_GIT_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")


def resolve_source_repo() -> str:
    """Return source_repo URI from env or the documented default."""
    return (os.environ.get("OVK_SOURCE_REPO") or DEFAULT_SOURCE_REPO).strip()


def resolve_source_commit(repo_root: Path | None = None) -> str:
    """Resolve git HEAD (40 hex) of the OVK repo. Fail closed — never all-zero."""
    root = repo_root or ovk_data_root()
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AssuranceError(
            f"unable to resolve OVK source_commit from git HEAD under {root}: {exc}"
        ) from exc
    commit = completed.stdout.strip().lower()
    if not _GIT_SHA40_RE.fullmatch(commit):
        raise AssuranceError(
            f"git HEAD must be a 40-hex commit SHA, got {commit!r} (all-zero placeholder forbidden)"
        )
    if commit == "0" * 40:
        raise AssuranceError("all-zero source_commit placeholder is forbidden")
    return commit


def producer_fields() -> dict[str, str]:
    """Return producer / producer_version for PCS artifacts."""
    return {
        "producer": PRODUCER_NAME,
        "producer_version": OVK_VERSION,
    }
