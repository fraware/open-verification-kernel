import json
from pathlib import Path

from scripts.run_authorization_obligation import main as authorization_main


def test_authorization_obligation_runner_writes_outputs(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_authorization_obligation.py",
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
    assert authorization_main() == 0
    assert evidence.exists()
    assert markdown.exists()
    assert attestation.exists()
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["evidence"][0]["intent"]["intent_id"] == "no-admin-route-bypass"


def test_authorization_obligation_runner_malformed_input_writes_unknown_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_authorization_obligation.py",
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
    assert authorization_main() == 0
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    evidence_item = payload["evidence"][0]
    assert evidence_item["backend_claims"][0]["status"] == "unknown"
    assert payload["decision"]["merge_recommendation"] == "require_human_review"
