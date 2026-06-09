import json
from pathlib import Path

from typer.testing import CliRunner

from ovk.cli import app


runner = CliRunner()


def test_infra_exposure_cli_blocks_public_sensitive_resource(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    result = runner.invoke(
        app,
        [
            "infra-exposure",
            "examples/infrastructure_exposure/input_public_sensitive_resource.json",
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
            "--advisory",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["decision"]["merge_recommendation"] == "block"
    assert markdown.exists()
    assert attestation.exists()


def test_infra_exposure_cli_allows_private_sensitive_resource(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    result = runner.invoke(
        app,
        [
            "infra-exposure",
            "examples/infrastructure_exposure/input_private_sensitive_resource.json",
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
            "--advisory",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["decision"]["merge_recommendation"] == "allow"
