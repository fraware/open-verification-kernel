from copy import deepcopy

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.core.bundle import make_bundle
from ovk.core.evidence_invariants import check_evidence_bundle_invariants
from ovk.core.models import EvidenceBundle


def _valid_bundle() -> EvidenceBundle:
    evidence = evaluate_infra_exposure(
        {
            "resources": [
                {
                    "resource_id": "bucket",
                    "resource_type": "object_storage_bucket",
                    "sensitivity": "confidential",
                    "public_exposure": False,
                    "exposure_paths": [],
                }
            ]
        },
        repo="example/repo",
        head_sha="abc",
    )
    return make_bundle([evidence])


def test_valid_bundle_has_no_invariant_errors() -> None:
    issues = check_evidence_bundle_invariants(_valid_bundle())
    errors = [issue for issue in issues if issue.severity == "error"]
    assert errors == []


def test_duplicate_evidence_ids_are_rejected() -> None:
    bundle = _valid_bundle()
    payload = bundle.model_dump(mode="json")
    payload["evidence"].append(deepcopy(payload["evidence"][0]))
    duplicate_bundle = EvidenceBundle.model_validate(payload)
    issues = check_evidence_bundle_invariants(duplicate_bundle)
    assert any("duplicate evidence_id" in issue.message for issue in issues)


def test_failing_claim_must_not_allow() -> None:
    bundle = _valid_bundle()
    payload = bundle.model_dump(mode="json")
    payload["evidence"][0]["backend_claims"][0]["status"] = "fail"
    payload["evidence"][0]["decision"]["merge_recommendation"] = "allow"
    unsafe_bundle = EvidenceBundle.model_validate(payload)
    issues = check_evidence_bundle_invariants(unsafe_bundle)
    assert any("failing backend claim" in issue.message for issue in issues)


def test_unknown_claim_requires_human_review() -> None:
    bundle = _valid_bundle()
    payload = bundle.model_dump(mode="json")
    payload["evidence"][0]["backend_claims"][0]["status"] = "unknown"
    payload["evidence"][0]["decision"]["human_review_required"] = False
    unsafe_bundle = EvidenceBundle.model_validate(payload)
    issues = check_evidence_bundle_invariants(unsafe_bundle)
    assert any("must require human review" in issue.message for issue in issues)
