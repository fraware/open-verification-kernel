from pathlib import Path

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.core.artifact_manifest import artifact_entry, build_artifact_manifest
from ovk.core.bundle import make_bundle
from ovk.core.json_io import read_json_file
from ovk.core.output_validation import (
    missing_release_layout_schema_coverage,
    validate_generated_file,
    validate_generated_json,
    validate_output_directory,
)
from ovk.core.release_bundle import ReleaseBundlePaths, release_bundle_layout, write_release_bundle


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


def test_artifact_manifest_validates_against_schema(tmp_path: Path) -> None:
    data = read_json_file(Path("examples/infrastructure_exposure/input_private_sensitive_resource.json"))
    bundle = make_bundle([evaluate_infra_exposure(data, repo="test/repo", head_sha="abc")])
    write_release_bundle(bundle, ReleaseBundlePaths(root=tmp_path))
    report = validate_generated_file(tmp_path / "ovk-artifact-manifest.json", "artifact_manifest")
    assert report.valid is True


def test_build_artifact_manifest_matches_schema(tmp_path: Path) -> None:
    evidence = tmp_path / "ovk-evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    manifest = build_artifact_manifest([artifact_entry(evidence, kind="evidence", root=tmp_path)])
    report = validate_generated_json(manifest, "artifact_manifest")
    assert report.valid is True


def test_release_layout_has_schema_coverage() -> None:
    assert missing_release_layout_schema_coverage(release_bundle_layout()) == []


def test_release_layout_validates_against_schema() -> None:
    report = validate_generated_json(release_bundle_layout(), "release_layout")
    assert report.valid is True
