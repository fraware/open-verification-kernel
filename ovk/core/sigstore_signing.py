"""Optional Sigstore/cosign signing for attestation envelopes."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


SIGSTORE_SIGNING_ENV = "OVK_SIGSTORE_SIGNING"
COSIGN_IDENTITY_ENV = "OVK_COSIGN_IDENTITY"
COSIGN_ISSUER_ENV = "OVK_COSIGN_ISSUER"


def cosign_available() -> bool:
    return shutil.which("cosign") is not None


def sigstore_signing_enabled() -> bool:
    """Return whether Sigstore signing is explicitly enabled."""
    return os.environ.get(SIGSTORE_SIGNING_ENV, "").strip().lower() in {"1", "true", "yes"}


def should_sign_with_cosign() -> bool:
    """Return whether all configured keyless-signing prerequisites exist."""
    return (
        sigstore_signing_enabled()
        and cosign_available()
        and bool(os.environ.get(COSIGN_IDENTITY_ENV))
        and bool(os.environ.get(COSIGN_ISSUER_ENV))
    )


def _configured_trust_identity() -> tuple[str, str]:
    identity = os.environ.get(COSIGN_IDENTITY_ENV, "").strip()
    issuer = os.environ.get(COSIGN_ISSUER_ENV, "").strip()
    if not identity or not issuer:
        raise RuntimeError("OVK Sigstore signing requires OVK_COSIGN_IDENTITY and OVK_COSIGN_ISSUER")
    return identity, issuer


def sign_envelope_with_cosign(
    envelope: dict[str, Any],
    *,
    bundle_path: str | Path,
) -> dict[str, Any]:
    """Attach a keyless cosign sign-blob bundle when signing is enabled."""
    if not sigstore_signing_enabled():
        return envelope
    if not cosign_available():
        raise RuntimeError("OVK Sigstore signing is enabled but cosign is not available")
    identity, issuer = _configured_trust_identity()

    bundle_file = Path(bundle_path)
    bundle_file.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(envelope, sort_keys=True, separators=(",", ":"))

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".json") as handle:
        handle.write(payload)
        payload_path = Path(handle.name)

    try:
        completed = subprocess.run(
            ["cosign", "sign-blob", "--yes", "--bundle", str(bundle_file), str(payload_path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "cosign sign-blob failed")
        try:
            bundle_data = json.loads(bundle_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(f"cosign did not produce a readable bundle: {error}") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("cosign sign-blob timed out") from error
    except OSError as error:
        raise RuntimeError(f"cosign sign-blob could not execute: {error}") from error
    finally:
        payload_path.unlink(missing_ok=True)

    return {
        **envelope,
        "sigstore": {
            "provider": "cosign",
            "bundle_path": str(bundle_file),
            "bundle": bundle_data,
            "status": "signed",
            "certificate_identity": identity,
            "certificate_oidc_issuer": issuer,
        },
    }


def verify_cosign_bundle(
    payload: bytes | str,
    bundle: dict[str, Any],
    *,
    certificate_identity: str,
    certificate_oidc_issuer: str,
) -> bool:
    """Verify a payload and bind it to an expected keyless signing identity."""
    if not cosign_available() or not certificate_identity or not certificate_oidc_issuer:
        return False
    payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload

    with tempfile.NamedTemporaryFile("wb", delete=False) as payload_file:
        payload_file.write(payload_bytes)
        payload_path = Path(payload_file.name)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".json") as bundle_file:
        json.dump(bundle, bundle_file)
        bundle_path = Path(bundle_file.name)

    try:
        result = subprocess.run(
            [
                "cosign",
                "verify-blob",
                "--bundle",
                str(bundle_path),
                "--certificate-identity",
                certificate_identity,
                "--certificate-oidc-issuer",
                certificate_oidc_issuer,
                str(payload_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        payload_path.unlink(missing_ok=True)
        bundle_path.unlink(missing_ok=True)
