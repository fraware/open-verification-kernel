import json
from pathlib import Path

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.core.bundle import make_bundle
from ovk.core.run_outputs import StandardOutputPaths, write_standard_run_outputs


def _bundle():
    evidence = evaluate_infra_exposure(
        {
            "resources": [
                {
                    "resource_id": "resource-a",
                    "resource_type": "storage",
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


def test_write_standard_run_outputs_writes_all_files(tmp_path: Path) -> None:
    paths = StandardOutputPaths(
        evidence=tmp_path / "evidence.json",
        markdown=tmp_path / "comment.md",
        attestation=tmp_path / "attestation.json",
        manifest=tmp_path / "manifest.json",
    )
    write_standard_run_outputs(_bundle(), paths)
    assert paths.evidence.exists()
    assert paths.markdown.exists()
    assert paths.attestation.exists()
    assert paths.manifest is not None and paths.manifest.exists()
    payload = json.loads(paths.manifest.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "ovk.artifact_manifest.v1"


def test_write_standard_run_outputs_can_write_quality_report(tmp_path: Path) -> None:
    paths = StandardOutputPaths(
        evidence=tmp_path / "evidence.json",
        markdown=tmp_path / "comment.md",
        attestation=tmp_path / "attestation.json",
        manifest=tmp_path / "manifest.json",
        quality_report=tmp_path / "quality.json",
    )
    write_standard_run_outputs(_bundle(), paths)
    assert paths.quality_report is not None and paths.quality_report.exists()
    payload = json.loads(paths.quality_report.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "ovk.evidence_quality.v1"
    assert payload["passed"] is True
