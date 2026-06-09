import json
from pathlib import Path

from scripts.write_standard_run_manifest import main as write_standard_manifest_main


def test_write_standard_run_manifest(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "evidence.json"
    markdown = tmp_path / "comment.md"
    attestation = tmp_path / "attestation.json"
    output = tmp_path / "manifest.json"
    evidence.write_text("{}\n", encoding="utf-8")
    markdown.write_text("# report\n", encoding="utf-8")
    attestation.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "write_standard_run_manifest.py",
            "--evidence",
            str(evidence),
            "--markdown",
            str(markdown),
            "--attestation",
            str(attestation),
            "--output",
            str(output),
        ],
    )
    assert write_standard_manifest_main() == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "ovk.artifact_manifest.v1"
    assert {item["kind"] for item in payload["artifacts"]} == {"evidence", "markdown", "attestation"}
