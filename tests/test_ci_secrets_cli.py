import json
from pathlib import Path

from typer.testing import CliRunner

from ovk.cli import app


runner = CliRunner()


def test_ci_secrets_cli_writes_quality_output(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    manifest = tmp_path / "manifest.json"
    quality = tmp_path / "quality.json"
    result = runner.invoke(
        app,
        [
            "ci-secrets",
            "examples/ci_secrets/input_secrets_safe.json",
            "--repo",
            "example/repo",
            "--head-sha",
            "abc",
            "--evidence-output",
            str(evidence),
            "--markdown-output",
            str(markdown),
            "--attestation-output",
            str(attestation),
            "--manifest-output",
            str(manifest),
            "--quality-output",
            str(quality),
            "--advisory",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(quality.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "ovk.evidence_quality.v1"
    assert payload["passed"] is True
