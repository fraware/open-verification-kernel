import json
from pathlib import Path

from typer.testing import CliRunner

from ovk.cli import app


runner = CliRunner()


def test_auth_obligation_cli_writes_outputs(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    result = runner.invoke(
        app,
        [
            "auth-obligation",
            "examples/auth_regression/input_admin_bypass.json",
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
    assert evidence.exists()
    assert markdown.exists()
    assert attestation.exists()
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["evidence"][0]["intent"]["intent_id"] == "no-admin-route-bypass"


def test_auth_obligation_cli_malformed_input_requires_review(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    result = runner.invoke(
        app,
        [
            "auth-obligation",
            "examples/auth_regression/input_malformed_missing_routes.json",
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
    assert payload["evidence"][0]["backend_claims"][0]["status"] == "unknown"
    assert payload["decision"]["merge_recommendation"] == "require_human_review"
