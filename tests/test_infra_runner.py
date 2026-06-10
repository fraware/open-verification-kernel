import json
from pathlib import Path

from scripts.run_infra_exposure import main as infra_main


def test_infra_runner_public_sensitive_resource_writes_blocking_outputs(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    manifest = tmp_path / "manifest.json"
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
            "--manifest-output",
            str(manifest),
            "--advisory",
        ],
    )
    assert infra_main() == 0
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["decision"]["merge_recommendation"] == "block"
    assert markdown.exists()
    assert attestation.exists()
    assert manifest_payload["schema_version"] == "ovk.artifact_manifest.v1"
    assert {item["kind"] for item in manifest_payload["artifacts"]} == {
        "evidence",
        "markdown",
        "attestation",
        "evidence_quality",
    }


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


def test_infra_runner_terraform_format_blocks(tmp_path: Path, monkeypatch) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "type": "aws_s3_bucket",
                        "name": "exports",
                        "change": {"after": {"tags": {"sensitivity": "restricted"}, "acl": "public-read"}},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_infra_exposure.py",
            str(plan),
            "--input-format",
            "terraform",
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


def test_infra_runner_kubernetes_format_blocks(tmp_path: Path, monkeypatch) -> None:
    manifest = tmp_path / "service.json"
    manifest.write_text(
        json.dumps(
            {
                "kind": "Service",
                "metadata": {"name": "api", "annotations": {"ovk.io/sensitivity": "restricted"}},
                "spec": {"type": "LoadBalancer"},
            }
        ),
        encoding="utf-8",
    )
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_infra_exposure.py",
            str(manifest),
            "--input-format",
            "kubernetes",
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


def test_infra_runner_policy_can_harden_internal_public_resource(tmp_path: Path, monkeypatch) -> None:
    infra_input = tmp_path / "infra.json"
    policy = tmp_path / "policy.json"
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    infra_input.write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "resource_id": "frontend",
                        "resource_type": "service",
                        "sensitivity": "internal",
                        "public_exposure": True,
                        "exposure_paths": ["internet_accessible"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    policy.write_text(json.dumps({"blocked_public_sensitivities": ["internal", "confidential"]}), encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_infra_exposure.py",
            str(infra_input),
            "--policy",
            str(policy),
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
