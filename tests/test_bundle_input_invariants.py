import pytest

from ovk.core.bundle import make_bundle
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


def _evidence(evidence_id: str, *, repo: str = "test/repo", head_sha: str = "abc") -> VerificationEvidence:
    return VerificationEvidence(
        evidence_id=evidence_id,
        subject={"repo": repo, "head_sha": head_sha},
        intent={"intent_id": evidence_id, "title": evidence_id, "risk": {"severity": "low"}},
        backend_claims=[
            BackendClaim(
                backend="test",
                guarantee_type="test",
                status=VerificationStatus.PASS,
                assumptions=["test"],
                limits=["test"],
                adapter_version="test",
            )
        ],
        decision={"merge_recommendation": "allow", "human_review_required": False},
    )


def test_make_bundle_rejects_subject_mismatch() -> None:
    with pytest.raises(ValueError, match="evidence subject mismatch"):
        make_bundle([_evidence("one"), _evidence("two", head_sha="def")])


def test_make_bundle_rejects_duplicate_evidence_ids() -> None:
    with pytest.raises(ValueError, match="duplicate evidence_id"):
        make_bundle([_evidence("same"), _evidence("same")])
