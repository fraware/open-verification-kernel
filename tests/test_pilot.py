import json
import subprocess
import sys
from pathlib import Path

from ovk.core.json_io import read_json_file
from ovk.core.pilot import run_pilot_manifest, run_pilot_program
from ovk.core.schema_validation import require_schema_valid


def test_pilot_program_all_manifests_allow() -> None:
    report = run_pilot_program()
    assert report["schema_version"] == "ovk.pilot_report.v1"
    assert report["manifests_total"] >= 5
    assert report["manifests_passed"] == report["manifests_total"]
    for result in report["results"]:
        assert result["passed"] is True
        assert result["merge_recommendation"] == "allow"


def test_pilot_full_mvp_manifest() -> None:
    result = run_pilot_manifest(Path("examples/pilot_repos/full_mvp.json"))
    assert result["name"] == "pilot-full-mvp"
    assert result["lane_count"] == 5
    assert result["passed"] is True


def test_pilot_wave1_backend_manifest() -> None:
    manifest = Path("examples/pilot_repos/wave1_backends.json")
    result = run_pilot_manifest(manifest)
    assert result["lane_count"] == 3
    assert result["passed"] is True


def test_pilot_wave2_backend_manifest() -> None:
    manifest = Path("examples/pilot_repos/wave2_backends.json")
    result = run_pilot_manifest(manifest)
    assert result["lane_count"] == 5
    assert result["passed"] is True


def test_pilot_report_matches_schema() -> None:
    report = run_pilot_program()
    schema = read_json_file(Path("schemas/pilot.report.schema.json"))
    require_schema_valid(report, schema, context="pilot report")


def test_pilot_cli_emits_report(tmp_path: Path) -> None:
    output = tmp_path / "pilot-report.json"
    result = subprocess.run(
        [sys.executable, "-m", "ovk.cli", "pilot", "--output", str(output)],
        cwd=Path("."),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["manifests_passed"] == payload["manifests_total"]
