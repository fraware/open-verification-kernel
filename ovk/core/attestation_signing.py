"""Optional HMAC signing for OVK attestation envelopes."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any


SIGNATURE_ALG = "hmac-sha256"
SIGNING_KEY_ENV = "OVK_SIGNING_KEY"


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def signing_key_from_environment() -> bytes | None:
    """Load an optional signing key from the environment."""
    raw = os.environ.get(SIGNING_KEY_ENV)
    if not raw:
        return None
    return raw.encode("utf-8")


def sign_payload(payload: dict[str, Any], key: bytes) -> dict[str, str]:
    """Return a signature object for a canonical JSON payload."""
    digest = hmac.new(key, _canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()
    return {"algorithm": SIGNATURE_ALG, "digest": digest}


def sign_envelope(envelope: dict[str, Any], key: bytes | None = None) -> dict[str, Any]:
    """Attach an HMAC signature to an attestation envelope when a key is available."""
    selected_key = key if key is not None else signing_key_from_environment()
    if selected_key is None:
        return envelope
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    return {**unsigned, "signature": sign_payload(unsigned, selected_key)}


def verify_envelope_signature(envelope: dict[str, Any], key: bytes | None = None) -> bool:
    """Verify an attestation envelope signature when present."""
    signature = envelope.get("signature")
    if not isinstance(signature, dict):
        return True
    selected_key = key if key is not None else signing_key_from_environment()
    if selected_key is None:
        return False
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    expected = sign_payload(unsigned, selected_key)
    return hmac.compare_digest(str(signature.get("digest", "")), expected["digest"])
