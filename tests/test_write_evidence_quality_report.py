import json
from pathlib import Path

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.core.bundle import make_bundle
from scripts.write_evidence_quality_report import main as write_evidence_quality_report


def test_write_evidence_quality_report_passes_for_valid_bundle(tmp_path: Path, monkeypatch) -> None:
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
    bundle_path = tmp_path / "bundle.json"
    report_path = tmp_path / "quality.json"
    bundle_path.write_text(json.dumps(make_bundle([evidence]).model_dump(mode="json")) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        ["write_evidence_quality_report.py", str(bundle_path), "--output", str(report_path)],
    )
    assert write_evidence_quality_report() == 0
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "ovk.evidence_quality.v1"
    assert payload["passed"] is True
    assert payload["issues"] == []
