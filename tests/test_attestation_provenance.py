from ovk.core.attestation import bundle_to_statement
from ovk.core.bundle import make_bundle
from ovk.core.models import VerificationEvidence, VerificationStatus


def test_attestation_includes_builder_provenance() -> None:
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
    statement = bundle_to_statement(make_bundle([evidence]))
    verification = statement["predicate"]["verification"]
    assert verification["bundle_digest"]
    builder = statement["predicate"]["builder"]
    assert builder["id"] == "open-verification-kernel"
    assert builder["version"] == "1.1.0"
    assert builder["runtime"].startswith("python/")
