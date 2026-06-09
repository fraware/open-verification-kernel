import json
from pathlib import Path

from ovk.core.artifact_manifest import artifact_entry, build_artifact_manifest, sha256_file
from scripts.write_artifact_manifest import main as write_manifest_main


def test_sha256_file_is_stable(tmp_path: Path) -> None:
    artifact = tmp_path / "evidence.json"
    artifact.write_text("hello\n", encoding="utf-8")
    assert sha256_file(artifact) == sha256_file(artifact)


def test_build_artifact_manifest_sorts_entries(tmp_path: Path) -> None:
    root = tmp_path
    evidence = root / "evidence.json"
    markdown = root / "comment.md"
    evidence.write_text("{}\n", encoding="utf-8")
    markdown.write_text("# report\n", encoding="utf-8")
    manifest = build_artifact_manifest(
        [
            artifact_entry(markdown, kind="markdown", root=root),
            artifact_entry(evidence, kind="evidence", root=root),
        ]
    )
    assert manifest["schema_version"] == "ovk.artifact_manifest.v1"
    assert [item["kind"] for item in manifest["artifacts"]] == ["evidence", "markdown"]


def test_write_artifact_manifest_script(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    output = tmp_path / "manifest.json"
    evidence.write_text("{}\n", encoding="utf-8")
    markdown.write_text("# report\n", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "write_artifact_manifest.py",
            "--artifact",
            str(evidence),
            "--artifact",
            str(markdown),
            "--kind",
            "evidence",
            "--kind",
            "markdown",
            "--root",
            str(tmp_path),
            "--output",
            str(output),
        ],
    )
    assert write_manifest_main() == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "ovk.artifact_manifest.v1"
    assert len(payload["artifacts"]) == 2
