import json
from pathlib import Path

from ovk.core.output_validation import validate_generated_json, validate_output_directory


def _failed_quality_report() -> dict:
    return {
        "schema_version": "ovk.evidence_quality.v1",
        "bundle_id": "bundle-forged",
        "passed": False,
        "issues": [
            {
                "path": "evidence[0].backend_claims[0].status",
                "message": "failing backend claim must not produce allow recommendation",
                "severity": "error",
            }
        ],
    }


def test_failed_quality_report_is_semantically_invalid() -> None:
    report = validate_generated_json(_failed_quality_report(), "quality_report")
    assert report.valid is False
    assert any("invariant errors" in issue.message for issue in report.issues)


def test_output_directory_rejects_failed_quality_report(tmp_path: Path) -> None:
    path = tmp_path / "ovk-evidence-quality.json"
    path.write_text(json.dumps(_failed_quality_report()), encoding="utf-8")
    failures = validate_output_directory(tmp_path)
    assert any("evidence quality report records invariant errors" in failure for failure in failures)
