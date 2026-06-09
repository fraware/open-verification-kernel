import json
from pathlib import Path

from scripts.write_standard_run_manifest import main as write_standard_manifest_main


def test_standard_run_manifest_root_option(tmp_path: Path, monkeypatch) -> None:
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
            "--root",
            str(tmp_path),
            "--output",
            str(output),
        ],
    )
    assert write_standard_manifest_main() == 0
    paths = {item["path"] for item in json.loads(output.read_text(encoding="utf-8"))["artifacts"]}
    assert paths == {"evidence.json", "comment.md", "attestation.json"}
