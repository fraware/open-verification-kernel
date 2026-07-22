"""Build provenance records for OVK release bundles."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from ovk import __version__
from ovk.core.artifact_manifest import sha256_file
from ovk.core.bundle import content_digest
from ovk.core.models import EvidenceBundle


PROVENANCE_SCHEMA_VERSION = "ovk.provenance.v1"


def _git_value(args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value or None


def git_provenance() -> dict[str, str]:
    """Collect best-effort git provenance from the local repository."""
    return {
        key: value
        for key, value in {
            "commit": _git_value(["rev-parse", "HEAD"]),
            "branch": _git_value(["rev-parse", "--abbrev-ref", "HEAD"]),
            "dirty": _git_value(["status", "--porcelain"]) or "",
        }.items()
        if value is not None
    }


def _material_uri(path: Path, *, workspace: Path | None = None) -> str:
    resolved = path.resolve()
    root = (workspace or Path.cwd()).resolve()
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return resolved.name


def material_entry(path: Path, *, workspace: Path | None = None) -> dict[str, Any]:
    """Describe one input material without leaking absolute local paths."""
    resolved = path.resolve()
    return {
        "uri": _material_uri(resolved, workspace=workspace),
        "digest": {"sha256": sha256_file(resolved)},
        "size_bytes": resolved.stat().st_size,
    }


def build_provenance_statement(
    bundle: EvidenceBundle,
    *,
    materials: list[Path] | None = None,
    invocation: dict[str, Any] | None = None,
    workspace: Path | None = None,
) -> dict[str, Any]:
    """Build an OVK provenance statement for a release bundle."""
    bundle_payload = bundle.model_dump(mode="json")
    return {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "builder": {
            "id": "open-verification-kernel",
            "version": __version__,
        },
        "bundle": {
            "bundle_id": bundle.bundle_id,
            "digest": {"sha256": content_digest(bundle_payload)},
            "decision": bundle.decision,
        },
        "materials": [material_entry(path, workspace=workspace) for path in materials or []],
        "invocation": invocation
        or {
            "config_source": {
                "entry_point": os.environ.get("OVK_INVOCATION", "ovk"),
            },
            "environment": {
                key: os.environ[key]
                for key in ("GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF")
                if key in os.environ
            },
        },
        "vcs": git_provenance(),
    }
