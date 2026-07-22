import json
from pathlib import Path

import pytest

from ovk.core.output_validation import validate_generated_json
from ovk.core.release_bundle import verify_release_bundle
from ovk.core.sigstore_signing import sign_envelope_with_cosign


def test_release_verifier_rejects_manifest_path_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-artifact.json"
    outside.write_text("{}", encoding="utf-8")
    manifest = {
        "schema_version": "ovk.artifact_manifest.v1",
        "artifacts": [
            {
                "path": "../outside-artifact.json",
                "kind": "evidence",
                "sha256": "0" * 64,
                "size_bytes": 2,
            }
        ],
    }
    (tmp_path / "ovk-artifact-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    failures = verify_release_bundle(tmp_path, layout={"schema_version": "ovk.release_layout.v1", "artifacts": []})
    assert any("escapes bundle root" in failure for failure in failures)


def test_sigstore_envelope_shape_is_schema_valid() -> None:
    envelope = {
        "schema_version": "ovk.attestation_envelope.v1",
        "statement": {},
        "artifact_manifest": {
            "path": "ovk-artifact-manifest.json",
            "kind": "artifact_manifest",
            "sha256": "0" * 64,
        },
        "sigstore": {
            "provider": "cosign",
            "bundle_path": "ovk-artifact-manifest.cosign.bundle.json",
            "bundle": {"verificationMaterial": {}},
            "status": "signed",
            "certificate_identity": "https://github.com/example/repo/.github/workflows/release.yml@refs/tags/v1.2.0",
            "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
        },
    }
    assert validate_generated_json(envelope, "attestation_envelope").valid is True


def test_explicit_sigstore_request_fails_when_cosign_missing(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OVK_SIGSTORE_SIGNING", "1")
    monkeypatch.setattr("ovk.core.sigstore_signing.shutil.which", lambda _name: None)
    with pytest.raises(RuntimeError, match="cosign is not available"):
        sign_envelope_with_cosign({}, bundle_path=tmp_path / "bundle.json")


def test_explicit_sigstore_request_requires_identity_and_issuer(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OVK_SIGSTORE_SIGNING", "1")
    monkeypatch.delenv("OVK_COSIGN_IDENTITY", raising=False)
    monkeypatch.delenv("OVK_COSIGN_ISSUER", raising=False)
    monkeypatch.setattr("ovk.core.sigstore_signing.shutil.which", lambda _name: "/usr/bin/cosign")
    with pytest.raises(RuntimeError, match="OVK_COSIGN_IDENTITY and OVK_COSIGN_ISSUER"):
        sign_envelope_with_cosign({}, bundle_path=tmp_path / "bundle.json")
