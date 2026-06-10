from pathlib import Path

from typer.testing import CliRunner

from ovk.cli import app
from ovk.core.multi_lane import load_verification_manifest, run_verification_manifest


def test_run_verification_manifest_full_mvp() -> None:
    manifest_path = Path("examples/verification_manifests/full_mvp.json")
    manifest = load_verification_manifest(manifest_path)
    bundle = run_verification_manifest(
        manifest,
        repo="test/repo",
        head_sha="abc",
        root=manifest_path.parent,
    )
    assert bundle.decision["merge_recommendation"] == "allow"
    assert len(bundle.evidence) == 5


def test_verify_cli_writes_bundle(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "verify",
            "--manifest",
            "examples/verification_manifests/full_mvp.json",
            "--output-dir",
            str(tmp_path),
            "--advisory",
        ],
    )
    assert result.exit_code == 0
    assert (tmp_path / "ovk-evidence.json").exists()
    assert (tmp_path / "ovk-attestation-envelope.json").exists()
