import json
from pathlib import Path

from scripts.run_infra_exposure import main as infra_main


def test_infra_runner_public_sensitive_resource_writes_blocking_outputs(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_infra_exposure.py",
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
    assert infra_main() == 0
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["decision"]["merge_recommendation"] == "block"
    assert markdown.exists()
    assert attestation.exists()


def test_infra_runner_private_sensitive_resource_allows(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_infra_exposure.py",
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
    assert infra_main() == 0
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["decision"]["merge_recommendation"] == "allow"
