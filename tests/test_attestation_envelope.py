import json
from pathlib import Path

from ovk.core.attestation_envelope import build_attestation_envelope
from scripts.write_attestation_envelope import main as write_envelope_main


def test_build_attestation_envelope_hashes_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema_version":"ovk.artifact_manifest.v1"}\n', encoding="utf-8")
    envelope = build_attestation_envelope(statement={"predicateType": "test"}, manifest_path=manifest)
    assert envelope["schema_version"] == "ovk.attestation_envelope.v1"
    assert envelope["artifact_manifest"]["sha256"]
    assert envelope["statement"]["predicateType"] == "test"


def test_write_attestation_envelope_script(tmp_path: Path, monkeypatch) -> None:
    statement = tmp_path / "attestation.json"
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "envelope.json"
    statement.write_text(json.dumps({"predicateType": "test"}), encoding="utf-8")
    manifest.write_text(json.dumps({"schema_version": "ovk.artifact_manifest.v1"}), encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "write_attestation_envelope.py",
            "--statement",
            str(statement),
            "--manifest",
            str(manifest),
            "--output",
            str(output),
        ],
    )
    assert write_envelope_main() == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "ovk.attestation_envelope.v1"
    assert payload["artifact_manifest"]["path"] == str(manifest)
