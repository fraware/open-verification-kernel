"""Standard OVK run artifact helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ovk.core.artifact_manifest import artifact_entry, build_artifact_manifest


STANDARD_ARTIFACT_KINDS = {
    "evidence": "evidence",
    "markdown": "markdown",
    "attestation": "attestation",
}


def standard_run_manifest(
    *,
    evidence_path: Path,
    markdown_path: Path,
    attestation_path: Path,
    root: Path | None = None,
) -> dict[str, Any]:
    """Build the canonical manifest for a standard OVK run."""
    return build_artifact_manifest(
        [
            artifact_entry(evidence_path, kind=STANDARD_ARTIFACT_KINDS["evidence"], root=root),
            artifact_entry(markdown_path, kind=STANDARD_ARTIFACT_KINDS["markdown"], root=root),
            artifact_entry(attestation_path, kind=STANDARD_ARTIFACT_KINDS["attestation"], root=root),
        ]
    )
