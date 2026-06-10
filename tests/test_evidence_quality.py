from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.core.bundle import make_bundle
from ovk.core.evidence_quality import EVIDENCE_QUALITY_SCHEMA_VERSION, build_evidence_quality_report
from ovk.core.models import EvidenceBundle


def _bundle() -> EvidenceBundle:
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


def test_evidence_quality_report_passes_for_valid_bundle() -> None:
    report = build_evidence_quality_report(_bundle())
    payload = report.to_dict()
    assert payload["schema_version"] == EVIDENCE_QUALITY_SCHEMA_VERSION
    assert payload["passed"] is True
    error_issues = [issue for issue in payload["issues"] if issue["severity"] == "error"]
    assert error_issues == []


def test_native_evidence_honesty_rejects_oracle_with_native_claim() -> None:
    from ovk.core.evidence_quality import build_evidence_quality_report
    from ovk.core.models import EvidenceBundle

    bundle = EvidenceBundle.model_validate(
        {
            "bundle_id": "bundle-test-native-honesty",
            "subject": {"repo": "example/repo", "head_sha": "abc123"},
            "decision": {"merge_recommendation": "block"},
            "evidence": [
                {
                    "evidence_id": "ev-native-honesty",
                    "subject": {"repo": "example/repo", "head_sha": "abc123"},
                    "intent": {"intent_id": "test", "risk": {"severity": "medium"}},
                    "backend_claims": [
                        {
                            "backend": "cbmc",
                            "guarantee_type": "native_tool",
                            "status": "fail",
                            "assumptions": ["cbmc deterministic oracle result used."],
                            "limits": ["test"],
                            "adapter_version": "0.1.0",
                        }
                    ],
                    "decision": {"merge_recommendation": "block"},
                    "generated_artifacts": [{"kind": "input_digest", "digest": "abc"}],
                }
            ],
        }
    )
    report = build_evidence_quality_report(bundle)
    assert report.passed is False
    assert any("OVK-INV-NATIVE-HONESTY" in issue.message for issue in report.issues)
    payload = _bundle().model_dump(mode="json")
    payload["evidence"][0]["backend_claims"][0]["status"] = "fail"
    payload["evidence"][0]["decision"]["merge_recommendation"] = "allow"
    report = build_evidence_quality_report(EvidenceBundle.model_validate(payload))
    data = report.to_dict()
    assert data["passed"] is False
    assert data["issues"]
