"""Attestation envelope helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ovk.core.artifact_manifest import sha256_file
from ovk.core.attestation_signing import sign_envelope
from ovk.core.sigstore_signing import sigstore_signing_enabled, sign_envelope_with_cosign


ENVELOPE_SCHEMA_VERSION = "ovk.attestation_envelope.v1"


def build_attestation_envelope(
    *,
    statement: dict[str, Any],
    manifest_path: Path,
    manifest_kind: str = "artifact_manifest",
    sign: bool = True,
) -> dict[str, Any]:
    """Bind an attestation statement to an artifact manifest digest and optionally sign it."""
    envelope = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "statement": statement,
        "artifact_manifest": {
            "path": str(manifest_path),
            "kind": manifest_kind,
            "sha256": sha256_file(manifest_path),
        },
    }
    if not sign:
        return envelope

    signed = sign_envelope(envelope)
    if sigstore_signing_enabled():
        sigstore_bundle = manifest_path.with_suffix(".cosign.bundle.json")
        return sign_envelope_with_cosign(signed, bundle_path=sigstore_bundle)
    return signed
