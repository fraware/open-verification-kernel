from ovk.core.attestation_envelope import build_attestation_envelope
from ovk.core.attestation_signing import sign_envelope, verify_envelope_signature
from ovk.core.bundle import make_bundle
from ovk.core.models import VerificationEvidence, VerificationStatus
from pathlib import Path


def _bundle():
    evidence = VerificationEvidence(
        evidence_id="ev-test",
        subject={"repo": "test/repo", "head_sha": "abc"},
        intent={"intent_id": "test", "title": "test"},
        backend_claims=[
            {
                "backend": "test",
                "guarantee_type": "test",
                "status": VerificationStatus.PASS,
            }
        ],
        decision={"merge_recommendation": "allow"},
    )
    return make_bundle([evidence])


def test_sign_and_verify_envelope(tmp_path: Path) -> None:
    from ovk.core.attestation import bundle_to_statement

    manifest = tmp_path / "ovk-artifact-manifest.json"
    manifest.write_text('{"artifacts":[]}\n', encoding="utf-8")
    envelope = build_attestation_envelope(
        statement=bundle_to_statement(_bundle()),
        manifest_path=manifest,
        sign=False,
    )
    key = b"test-signing-key"
    signed = sign_envelope(envelope, key=key)
    assert signed.get("signature")
    assert verify_envelope_signature(signed, key=key) is True
    assert verify_envelope_signature(signed, key=b"wrong-key") is False
