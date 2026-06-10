from pathlib import Path

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.core.bundle import make_bundle
from ovk.core.json_io import read_json_file
from ovk.core.release_bundle import ReleaseBundlePaths, verify_release_bundle, write_release_bundle


def test_release_bundle_round_trip(tmp_path: Path) -> None:
    data = read_json_file(Path("examples/infrastructure_exposure/input_private_sensitive_resource.json"))
    bundle = make_bundle([evaluate_infra_exposure(data, repo="test/repo", head_sha="abc")])
    write_release_bundle(bundle, ReleaseBundlePaths(root=tmp_path))
    assert verify_release_bundle(tmp_path) == []
    for name in (
        "ovk-evidence.json",
        "ovk-pr-comment.md",
        "ovk-attestation.json",
        "ovk-artifact-manifest.json",
        "ovk-evidence-quality.json",
        "ovk-provenance.json",
        "ovk-attestation-envelope.json",
    ):
        assert (tmp_path / name).exists()
