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
    assert payload["issues"] == []


def test_evidence_quality_report_records_issues() -> None:
    payload = _bundle().model_dump(mode="json")
    payload["evidence"][0]["backend_claims"][0]["status"] = "fail"
    payload["evidence"][0]["decision"]["merge_recommendation"] = "allow"
    report = build_evidence_quality_report(EvidenceBundle.model_validate(payload))
    data = report.to_dict()
    assert data["passed"] is False
    assert data["issues"]
