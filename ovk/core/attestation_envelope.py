"""Attestation envelope helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ovk.core.artifact_manifest import sha256_file


ENVELOPE_SCHEMA_VERSION = "ovk.attestation_envelope.v1"


def build_attestation_envelope(
    *,
    statement: dict[str, Any],
    manifest_path: Path,
    manifest_kind: str = "artifact_manifest",
) -> dict[str, Any]:
    """Bind an unsigned attestation statement to an artifact manifest digest."""
    return {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "statement": statement,
        "artifact_manifest": {
            "path": str(manifest_path),
            "kind": manifest_kind,
            "sha256": sha256_file(manifest_path),
        },
    }
