from pathlib import Path

from typer.testing import CliRunner

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.cli import app
from ovk.core.bundle import make_bundle
from ovk.core.json_io import read_json_file
from ovk.core.release_bundle import ReleaseBundlePaths, write_release_bundle


def test_validate_outputs_cli_passes_for_valid_bundle(tmp_path: Path) -> None:
    data = read_json_file(Path("examples/infrastructure_exposure/input_private_sensitive_resource.json"))
    bundle = make_bundle([evaluate_infra_exposure(data, repo="test/repo", head_sha="abc")])
    write_release_bundle(bundle, ReleaseBundlePaths(root=tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["validate-outputs", str(tmp_path)])
    assert result.exit_code == 0
    assert "OVK output validation passed" in result.stdout
