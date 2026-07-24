"""Adversarial secret redaction coverage for assurance exports."""

from __future__ import annotations

from ovk.assurance.pcs_export import snapshot_to_verifier_profile
from ovk.assurance.redaction import (
    is_secret_key,
    looks_like_secret_value,
    redact_environment,
    redact_mapping,
)
from ovk.assurance.snapshot import build_configuration_snapshot


def test_secret_keys_detected() -> None:
    assert is_secret_key("GITHUB_TOKEN")
    assert is_secret_key("MY_API_KEY")
    assert is_secret_key("db_password")
    assert is_secret_key("SERVICE_SECRET")
    assert is_secret_key("TLS_PRIVATE_KEY")
    assert is_secret_key("PGPASSWORD")
    assert is_secret_key("DATABASE_URL")
    assert is_secret_key("MYSQL_PWD")
    assert is_secret_key("connection_string")
    assert is_secret_key("JWT")
    assert not is_secret_key("PATH")
    assert not is_secret_key("CI")
    assert not is_secret_key("HISTORY")


def test_secret_value_patterns() -> None:
    assert looks_like_secret_value("ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    assert looks_like_secret_value("sk-abcdefghijklmnopqrstuvwxyz012345")
    assert looks_like_secret_value("Authorization: Bearer abc.def.ghi")
    assert looks_like_secret_value("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")
    assert not looks_like_secret_value("ordinary note")


def test_redact_environment_strips_secrets_and_digests() -> None:
    env = {
        "PATH": "/usr/bin",
        "CI": "true",
        "GITHUB_TOKEN": "ghp_secret",
        "OPENAI_API_KEY": "sk-secret",
        "CUSTOM_PASSWORD": "hunter2",
        "NOTE": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
    }
    redacted = redact_environment(env)
    assert redacted["redaction_policy_id"] == "ovk-redact-v1"
    assert "GITHUB_TOKEN" not in redacted["entries"]
    assert "OPENAI_API_KEY" not in redacted["entries"]
    assert "CUSTOM_PASSWORD" not in redacted["entries"]
    assert "NOTE" not in redacted["entries"]
    assert redacted["entries"]["PATH"] == "/usr/bin"
    assert "GITHUB_TOKEN" in redacted["redacted_keys"]
    assert redacted["environment_digest"].startswith("sha256:")
    blob = str(redacted)
    assert "ghp_secret" not in blob
    assert "sk-secret" not in blob
    assert "hunter2" not in blob
    assert "Bearer eyJ" not in blob


def test_redact_mapping_recurses_lists_and_values() -> None:
    cleaned, redacted_keys = redact_mapping(
        {
            "ok": 1,
            "PASSWORD": "x",
            "nested": {"TOKEN": "y"},
            "headers": [{"Authorization": "Bearer abc.def.ghi"}, {"ok": True}],
            "note": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        }
    )
    assert cleaned["ok"] == 1
    assert cleaned["nested"] == {}
    assert cleaned["headers"] == [{}, {"ok": True}]
    assert "note" not in cleaned
    assert "PASSWORD" in redacted_keys
    assert any("TOKEN" in item for item in redacted_keys)


def test_secrets_absent_from_snapshot_and_profile_export() -> None:
    snapshot = build_configuration_snapshot(
        backend_id="test-backend",
        adapter_id="test-adapter",
        adapter_version="0.1.0",
        config={"timeout_ms": 1000, "API_TOKEN": "should-not-leak", "threshold": 1},
        environment={"PATH": "/bin", "GH_TOKEN": "secret-token", "CI": "1"},
        mechanism_class="static_analysis",
        guarantee_class="observational",
        supported_claim_ids=["claim.test"],
    )
    assert "API_TOKEN" not in snapshot.config
    assert "GH_TOKEN" not in snapshot.redacted_environment["entries"]
    profile = snapshot_to_verifier_profile(snapshot)
    serialized = str(profile)
    assert "should-not-leak" not in serialized
    assert "secret-token" not in serialized
