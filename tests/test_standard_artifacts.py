from pathlib import Path

from ovk.core.standard_artifacts import standard_run_manifest


def test_standard_run_manifest_contains_three_artifacts(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    evidence.write_text("{}\n", encoding="utf-8")
    markdown.write_text("# report\n", encoding="utf-8")
    attestation.write_text("{}\n", encoding="utf-8")
    manifest = standard_run_manifest(
        evidence_path=evidence,
        markdown_path=markdown,
        attestation_path=attestation,
        root=tmp_path,
    )
    assert manifest["schema_version"] == "ovk.artifact_manifest.v1"
    assert {item["kind"] for item in manifest["artifacts"]} == {"evidence", "markdown", "attestation"}
    assert {item["path"] for item in manifest["artifacts"]} == {"evidence.json", "comment.md", "attestation.json"}
