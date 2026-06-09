import json
from pathlib import Path

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.core.bundle import make_bundle
from scripts.check_evidence_invariants import main as check_evidence_invariants


def test_check_evidence_invariants_script_passes_for_valid_bundle(tmp_path: Path, monkeypatch) -> None:
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
    bundle_path.write_text(json.dumps(make_bundle([evidence]).model_dump(mode="json")) + "\n", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["check_evidence_invariants.py", str(bundle_path)])
    assert check_evidence_invariants() == 0
