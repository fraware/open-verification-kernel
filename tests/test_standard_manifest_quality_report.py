import json
from pathlib import Path

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.core.bundle import make_bundle
from ovk.core.run_outputs import StandardOutputPaths, write_standard_run_outputs


def test_standard_manifest_includes_quality_report_when_present(tmp_path: Path) -> None:
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
    paths = StandardOutputPaths(
        evidence=tmp_path / "evidence.json",
        markdown=tmp_path / "comment.md",
        attestation=tmp_path / "attestation.json",
        manifest=tmp_path / "manifest.json",
        quality_report=tmp_path / "quality.json",
    )
    write_standard_run_outputs(make_bundle([evidence]), paths)
    manifest = json.loads(paths.manifest.read_text(encoding="utf-8"))  # type: ignore[union-attr]
    assert "evidence_quality" in {artifact["kind"] for artifact in manifest["artifacts"]}
