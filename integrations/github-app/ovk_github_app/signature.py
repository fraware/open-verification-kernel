"""GitHub webhook HMAC-SHA256 signature verification."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from ovk_github_app.errors import SignatureError

SIGNATURE_HEADER = "X-Hub-Signature-256"
SIGNATURE_PREFIX = "sha256="


def compute_signature(*, secret: str | bytes, body: bytes) -> str:
    """Return the ``sha256=<hex>`` digest for ``body`` under ``secret``."""
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    digest = hmac.new(key, body, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_PREFIX}{digest}"


def verify_signature(
    *,
    secret: str | bytes,
    body: bytes,
    signature_header: str | None,
) -> None:
    """Verify ``X-Hub-Signature-256``; reject missing or invalid signatures.

    Uses constant-time comparison. Empty secrets are rejected so misconfigured
    deployments fail closed rather than accepting unsigned traffic.
    """
    if not secret:
        raise SignatureError("webhook secret is not configured")
    if signature_header is None or not str(signature_header).strip():
        raise SignatureError("missing X-Hub-Signature-256 header")

    expected = compute_signature(secret=secret, body=body)
    provided = str(signature_header).strip()
    if not provided.startswith(SIGNATURE_PREFIX):
        raise SignatureError("invalid webhook signature")
    if not hmac.compare_digest(expected, provided):
        raise SignatureError("invalid webhook signature")


def new_webhook_secret(*, nbytes: int = 32) -> str:
    """Generate a high-entropy webhook secret for private-alpha installs."""
    return secrets.token_hex(nbytes)
