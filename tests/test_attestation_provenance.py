from ovk.core.attestation import bundle_to_statement
from ovk.core.bundle import make_bundle
from ovk.core.models import VerificationEvidence, VerificationStatus
from ovk.core.output_validation import validate_generated_json


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
    assert builder["version"] == "1.2.1"
    assert builder["runtime"].startswith("python/")


def test_attestation_statement_validates_against_schema() -> None:
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
    report = validate_generated_json(statement, "attestation")
    assert report.valid is True, [issue.message for issue in report.issues]
