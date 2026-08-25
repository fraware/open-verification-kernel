"""Webhook HMAC signature verification tests (OVK-PR7)."""

from __future__ import annotations

import pytest

from ovk_github_app.errors import SignatureError
from ovk_github_app.signature import compute_signature, verify_signature


def test_verify_signature_accepts_valid_hmac() -> None:
    secret = "test-webhook-secret"
    body = b'{"action":"opened"}'
    header = compute_signature(secret=secret, body=body)
    verify_signature(secret=secret, body=body, signature_header=header)


def test_verify_signature_rejects_missing() -> None:
    with pytest.raises(SignatureError, match="missing"):
        verify_signature(secret="s", body=b"{}", signature_header=None)
    with pytest.raises(SignatureError, match="missing"):
        verify_signature(secret="s", body=b"{}", signature_header="  ")


def test_verify_signature_rejects_invalid() -> None:
    secret = "test-webhook-secret"
    body = b'{"ok":true}'
    with pytest.raises(SignatureError, match="invalid"):
        verify_signature(
            secret=secret,
            body=body,
            signature_header="sha256=" + ("ab" * 32),
        )


def test_verify_signature_rejects_empty_secret() -> None:
    with pytest.raises(SignatureError, match="not configured"):
        verify_signature(secret="", body=b"{}", signature_header="sha256=abc")


def test_verify_signature_rejects_wrong_secret() -> None:
    body = b'{"x":1}'
    header = compute_signature(secret="correct", body=body)
    with pytest.raises(SignatureError, match="invalid"):
        verify_signature(secret="wrong", body=body, signature_header=header)


def test_verify_signature_rejects_prefixless_digest() -> None:
    secret = "s"
    body = b"{}"
    digest = compute_signature(secret=secret, body=body).removeprefix("sha256=")
    with pytest.raises(SignatureError, match="invalid"):
        verify_signature(secret=secret, body=body, signature_header=digest)
