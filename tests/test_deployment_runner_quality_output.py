import json
from pathlib import Path

from scripts.run_deployment_state import main as deployment_main


def test_deployment_runner_writes_quality_output(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    manifest = tmp_path / "manifest.json"
    quality = tmp_path / "quality.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_deployment_state.py",
            "examples/deployment_state/input_valid_approval_path.json",
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
    assert deployment_main() == 0
    payload = json.loads(quality.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "ovk.evidence_quality.v1"
    assert payload["passed"] is True
    error_issues = [issue for issue in payload["issues"] if issue["severity"] == "error"]
    assert error_issues == []
