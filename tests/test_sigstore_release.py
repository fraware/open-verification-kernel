"""Unit tests for protected-release Sigstore helpers (no live Fulcio)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.core.sigstore_release import (
    DEFAULT_OIDC_ISSUER,
    SignedArtifact,
    github_certificate_identity,
    production_tag_identity,
    require_immutable_tag_ref,
    sign_and_verify_release,
    tamper_test,
    write_summary,
)


def test_github_certificate_identity_from_workflow_ref() -> None:
    identity = github_certificate_identity(
        workflow_ref=("fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/v1.2.0")
    )
    assert identity == (
        "https://github.com/fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/v1.2.0"
    )


def test_github_certificate_identity_rejects_foreign_repo() -> None:
    with pytest.raises(ValueError, match="unexpected workflow_ref"):
        github_certificate_identity(workflow_ref="evil/repo/.github/workflows/publish.yml@refs/tags/v1.2.0")


def test_production_tag_identity_matches_release_policy() -> None:
    assert production_tag_identity("v1.2.0") == (
        "https://github.com/fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/v1.2.0"
    )
    assert production_tag_identity("refs/tags/v1.2.0") == production_tag_identity("v1.2.0")


def test_require_immutable_tag_ref() -> None:
    require_immutable_tag_ref("refs/tags/v1.2.0")
    with pytest.raises(ValueError, match="immutable tag"):
        require_immutable_tag_ref("refs/heads/main")


def test_write_summary_shape(tmp_path: Path) -> None:
    summary_path = tmp_path / "summary.json"
    payload = write_summary(
        summary_path,
        identity=production_tag_identity("v1.2.0"),
        issuer=DEFAULT_OIDC_ISSUER,
        signed=[
            SignedArtifact(
                artifact=str(tmp_path / "pkg.whl"),
                bundle=str(tmp_path / "pkg.whl.cosign.bundle.json"),
                sha256="a" * 64,
            )
        ],
    )
    assert payload["schema_version"] == "ovk.sigstore_release_summary.v1"
    assert payload["certificate_oidc_issuer"] == DEFAULT_OIDC_ISSUER
    assert summary_path.is_file()
    loaded = json.loads(summary_path.read_text(encoding="utf-8"))
    assert loaded["artifacts"][0]["sha256"] == "a" * 64


def test_sign_verify_tamper_orchestration(monkeypatch, tmp_path: Path) -> None:
    artifact = tmp_path / "ovk-1.2.0-py3-none-any.whl"
    artifact.write_bytes(b"wheel-bytes")
    bundles = tmp_path / "bundles"
    calls: list[tuple[str, ...]] = []

    def fake_sign(path: Path, bundle_path: Path) -> None:
        calls.append(("sign", path.name))
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        bundle_path.write_text(
            '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}',
            encoding="utf-8",
        )

    def fake_verify(
        path: Path,
        bundle_path: Path,
        *,
        certificate_identity: str,
        certificate_oidc_issuer: str,
    ) -> None:
        del certificate_identity, certificate_oidc_issuer
        calls.append(("verify", path.name, bundle_path.name))
        if path.name.endswith(".tampered"):
            raise RuntimeError("expected tamper failure")

    monkeypatch.setattr("ovk.core.sigstore_release.sign_blob", fake_sign)
    monkeypatch.setattr("ovk.core.sigstore_release.verify_blob", fake_verify)

    signed = sign_and_verify_release(
        [artifact],
        bundles_dir=bundles,
        certificate_identity=production_tag_identity("v1.2.0"),
        certificate_oidc_issuer=DEFAULT_OIDC_ISSUER,
        require_tag=True,
        git_ref="refs/tags/v1.2.0",
    )
    assert len(signed) == 1
    assert Path(signed[0].bundle).is_file()
    assert ("sign", artifact.name) in calls
    assert any(call[0] == "verify" and call[1] == artifact.name for call in calls)
    assert any(call[0] == "verify" and str(call[1]).endswith(".tampered") for call in calls)


def test_tamper_test_fails_open_when_verify_succeeds(monkeypatch, tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"clean")
    bundle = tmp_path / "artifact.bin.cosign.bundle.json"
    bundle.write_text("{}", encoding="utf-8")

    monkeypatch.setattr("ovk.core.sigstore_release.verify_blob", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError, match="tamper test failed open"):
        tamper_test(
            artifact,
            bundle,
            certificate_identity=production_tag_identity("v1.2.0"),
            certificate_oidc_issuer=DEFAULT_OIDC_ISSUER,
        )


def test_require_tag_blocks_branch_dry_run_misuse(tmp_path: Path) -> None:
    artifact = tmp_path / "a.whl"
    artifact.write_bytes(b"x")
    with pytest.raises(ValueError, match="immutable tag"):
        sign_and_verify_release(
            [artifact],
            bundles_dir=tmp_path / "b",
            certificate_identity=production_tag_identity("v1.2.0"),
            require_tag=True,
            git_ref="refs/heads/main",
        )
