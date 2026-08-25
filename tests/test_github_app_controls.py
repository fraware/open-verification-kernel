"""Remaining GitHub App alpha controls: tokens, cache, checks, redact, webhook."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import pytest

from ovk.core.github_check import check_run_external_id
from ovk_github_app.cache_keys import app_cache_key, assert_cache_key_bound
from ovk_github_app.check_runs import app_check_run_external_id, build_check_run_update_payload
from ovk_github_app.errors import IsolationError, TokenError
from ovk_github_app.isolation import InstallationStore
from ovk_github_app.redact import RedactingFilter, redact_message, redact_path, redact_secrets
from ovk_github_app.replay import MemoryDeliveryDedupeStore
from ovk_github_app.signature import compute_signature
from ovk_github_app.tokens import InstallationTokenProvider
from ovk_github_app.webhook import WebhookProcessor


def test_check_run_external_id_aligns_with_pr6() -> None:
    repo = "acme/widgets"
    sha = "deadbeefcafebabe"
    assert app_check_run_external_id(repo=repo, head_sha=sha) == check_run_external_id(
        repo=repo, head_sha=sha
    )
    assert app_check_run_external_id(repo=repo, head_sha=sha) == f"ovk:{repo}:{sha}"


def test_check_run_payload_is_idempotent_per_head_sha() -> None:
    a = build_check_run_update_payload(
        repo="o/r",
        head_sha="abc",
        conclusion="success",
        title="t",
        summary="s",
    )
    b = build_check_run_update_payload(
        repo="o/r",
        head_sha="abc",
        conclusion="failure",
        title="t2",
        summary="s2",
    )
    assert a["external_id"] == b["external_id"] == "ovk:o/r:abc"


def test_cache_key_includes_installation_and_repo() -> None:
    k1 = app_cache_key(installation_id=1, repo_id=10, namespace="pull_request", components={"a": 1})
    k2 = app_cache_key(installation_id=2, repo_id=10, namespace="pull_request", components={"a": 1})
    k3 = app_cache_key(installation_id=1, repo_id=11, namespace="pull_request", components={"a": 1})
    assert k1 != k2
    assert k1 != k3
    assert k2 != k3


def test_cache_key_rejects_missing_binding() -> None:
    with pytest.raises(IsolationError):
        app_cache_key(installation_id="", repo_id=1, namespace="x")
    with pytest.raises(IsolationError):
        assert_cache_key_bound({"repo_id": 1}, installation_id=1, repo_id=1)


def test_token_provider_exchanges_on_demand_and_rejects_pat() -> None:
    now = int(time.time())
    calls: list[str] = []

    def fake_jwt(**kwargs):  # noqa: ANN003
        return "app-jwt"

    def fake_http(url: str, headers: dict[str, str], body: bytes | None):
        calls.append(url)
        assert headers["Authorization"] == "Bearer app-jwt"
        assert "ghp_" not in (body or b"").decode()
        return (
            201,
            {
                "token": "ghs_installation_short",
                "expires_at": now + 3600,
                "permissions": {"checks": "write", "contents": "read"},
            },
        )

    provider = InstallationTokenProvider(
        app_id=42,
        private_key_pem="-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----",
        jwt_builder=fake_jwt,
        http_post=fake_http,
    )
    token = provider.get_token(7, now=now)
    assert token.token.startswith("ghs_")
    assert token.expires_at == now + 3600
    assert len(calls) == 1
    # Cached within lifetime — no second exchange.
    again = provider.get_token(7, now=now + 10)
    assert again.token == token.token
    assert len(calls) == 1

    def pat_http(url: str, headers: dict[str, str], body: bytes | None):
        return (201, {"token": "ghp_long_lived_pat_value_xxxxxxxxxxxx", "expires_at": now + 100})

    bad = InstallationTokenProvider(
        app_id=42,
        private_key_pem="x",
        jwt_builder=fake_jwt,
        http_post=pat_http,
    )
    with pytest.raises(TokenError, match="personal access token"):
        bad.get_token(1, now=now)


def test_token_provider_rejects_oversized_lifetime() -> None:
    now = int(time.time())

    def fake_http(url: str, headers: dict[str, str], body: bytes | None):
        return (201, {"token": "ghs_x", "expires_at": now + 7200})

    provider = InstallationTokenProvider(
        app_id=1,
        private_key_pem="x",
        jwt_builder=lambda **_: "jwt",
        http_post=fake_http,
    )
    with pytest.raises(TokenError, match="lifetime"):
        provider.get_token(1, now=now)


def test_redact_paths_and_secrets() -> None:
    assert "<home>" in redact_path("/Users/mateo/secret/repo/file.py")
    assert "mateo" not in redact_path("/Users/mateo/secret/repo/file.py")
    assert "<redacted-token>" in redact_secrets("token=ghp_abcdefghijklmnopqrstuvwxyz012345")
    msg = redact_message(
        "auth Authorization: Bearer ghs_abcdefghijklmnopqrstuvwxyz path=/Users/mateo/proj/a.py"
    )
    assert "ghs_" not in msg
    assert "mateo" not in msg
    assert "<home>" in msg or "<redacted>" in msg


def test_redacting_filter_on_logger(caplog: pytest.LogCaptureFixture) -> None:
    log = logging.getLogger("ovk_github_app.test_redact")
    log.addFilter(RedactingFilter())
    log.setLevel(logging.INFO)
    with caplog.at_level(logging.INFO, logger="ovk_github_app.test_redact"):
        log.info("key ghp_abcdefghijklmnopqrstuvwxyz012345 at /Users/mateo/x")
    text = " ".join(r.message for r in caplog.records)
    assert "ghp_" not in text
    assert "mateo" not in text


def test_webhook_processor_happy_path_and_idempotent_external_id(tmp_path: Path) -> None:
    secret = "whsec"
    store = InstallationStore(tmp_path)
    processor = WebhookProcessor(
        webhook_secret=secret,
        store=store,
        dedupe=MemoryDeliveryDedupeStore(),
        require_timestamp_header=True,
        max_skew_seconds=300,
    )
    now = int(time.time())
    payload = {
        "action": "opened",
        "installation": {"id": 55},
        "repository": {"id": 9001, "full_name": "acme/widgets"},
        "pull_request": {"head": {"sha": "abc123"}},
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": compute_signature(secret=secret, body=body),
        "X-GitHub-Delivery": "del-1",
        "X-GitHub-Event": "pull_request",
        "X-OVK-Timestamp": str(now),
    }
    result = processor.process(headers=headers, body=body, now=now)
    assert result.status_code == 200
    assert result.body["ok"] is True
    assert result.body["external_id"] == "ovk:acme/widgets:abc123"
    assert result.body["installation_id"] == 55
    assert result.body["repo_id"] == 9001
    # Replay same delivery → 409
    replay = processor.process(headers=headers, body=body, now=now)
    assert replay.status_code == 409


def test_webhook_rejects_missing_signature(tmp_path: Path) -> None:
    processor = WebhookProcessor(
        webhook_secret="s",
        store=InstallationStore(tmp_path),
        dedupe=MemoryDeliveryDedupeStore(),
    )
    now = int(time.time())
    result = processor.process(
        headers={
            "X-GitHub-Delivery": "d1",
            "X-GitHub-Event": "ping",
            "X-OVK-Timestamp": str(now),
        },
        body=b"{}",
        now=now,
    )
    assert result.status_code == 401


def test_webhook_installation_deleted(tmp_path: Path) -> None:
    secret = "s"
    store = InstallationStore(tmp_path)
    store.write_json(77, "x.json", {"v": 1})
    processor = WebhookProcessor(
        webhook_secret=secret,
        store=store,
        dedupe=MemoryDeliveryDedupeStore(),
    )
    now = int(time.time())
    payload = {"action": "deleted", "installation": {"id": 77}}
    body = json.dumps(payload).encode("utf-8")
    result = processor.process(
        headers={
            "X-Hub-Signature-256": compute_signature(secret=secret, body=body),
            "X-GitHub-Delivery": "del-uninstall",
            "X-GitHub-Event": "installation",
            "X-OVK-Timestamp": str(now),
        },
        body=body,
        now=now,
    )
    assert result.status_code == 200
    assert result.body["handled"] == "installation.deleted"
    assert not (tmp_path / "installations" / "77").exists()


def test_manifest_is_private_with_least_privilege() -> None:
    manifest_path = (
        Path(__file__).resolve().parents[1] / "integrations" / "github-app" / "manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["public"] is False
    perms = manifest["default_permissions"]
    assert perms["checks"] == "write"
    assert perms["contents"] == "read"
    assert perms["pull_requests"] == "read"
    # No broad admin / workflows / members permissions.
    for forbidden in ("administration", "members", "workflows", "actions"):
        assert forbidden not in perms
