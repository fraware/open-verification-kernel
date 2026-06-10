from pathlib import Path

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.core.bundle import make_bundle
from ovk.core.json_io import read_json_file
from ovk.core.output_validation import validate_generated_file, validate_output_directory
from ovk.core.release_bundle import ReleaseBundlePaths, write_release_bundle


def test_generated_evidence_validates_against_bundle_schema(tmp_path: Path) -> None:
    data = read_json_file(Path("examples/infrastructure_exposure/input_private_sensitive_resource.json"))
    bundle = make_bundle([evaluate_infra_exposure(data, repo="test/repo", head_sha="abc")])
    write_release_bundle(bundle, ReleaseBundlePaths(root=tmp_path))
    assert validate_output_directory(tmp_path) == []


def test_quality_report_validates_against_schema(tmp_path: Path) -> None:
    data = read_json_file(Path("examples/infrastructure_exposure/input_private_sensitive_resource.json"))
    bundle = make_bundle([evaluate_infra_exposure(data, repo="test/repo", head_sha="abc")])
    write_release_bundle(bundle, ReleaseBundlePaths(root=tmp_path))
    report = validate_generated_file(tmp_path / "ovk-evidence-quality.json", "quality_report")
    assert report.valid is True
