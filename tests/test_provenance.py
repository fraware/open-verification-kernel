from pathlib import Path

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.core.bundle import make_bundle, content_digest
from ovk.core.json_io import read_json_file
from ovk.core.provenance import build_provenance_statement, material_entry
from ovk.core.release_bundle import ReleaseBundlePaths, write_release_bundle


def test_provenance_includes_bundle_digest() -> None:
    data = read_json_file(Path("examples/infrastructure_exposure/input_private_sensitive_resource.json"))
    bundle = make_bundle([evaluate_infra_exposure(data, repo="test/repo", head_sha="abc")])
    statement = build_provenance_statement(bundle)
    assert statement["bundle"]["digest"]["sha256"] == content_digest(bundle.model_dump(mode="json"))


def test_material_entry_resolves_relative_paths() -> None:
    entry = material_entry(Path("examples/infrastructure_exposure/input_private_sensitive_resource.json"))
    assert entry["uri"] == "examples/infrastructure_exposure/input_private_sensitive_resource.json"
    assert not Path(entry["uri"]).is_absolute()
    assert ":" not in entry["uri"].split("/", 1)[0]
    assert entry["digest"]["sha256"]
    assert entry["size_bytes"] > 0


def test_release_bundle_writes_provenance(tmp_path: Path) -> None:
    data = read_json_file(Path("examples/infrastructure_exposure/input_private_sensitive_resource.json"))
    bundle = make_bundle([evaluate_infra_exposure(data, repo="test/repo", head_sha="abc")])
    write_release_bundle(bundle, ReleaseBundlePaths(root=tmp_path))
    provenance = read_json_file(tmp_path / "ovk-provenance.json")
    assert provenance["schema_version"] == "ovk.provenance.v1"
