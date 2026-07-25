"""Tests for reproducible baseline schema validation (OVK-01)."""

from __future__ import annotations

from scripts.record_repro_baseline import validate_baseline_record


def _complete_baseline(**overrides: object) -> dict:
    payload = {
        "schema_version": "ovk.repro_baseline.v1",
        "python_version": "3.12.0",
        "os": "linux",
        "platform": "Linux-test",
        "network_access": True,
        "started_at": "2026-07-25T00:00:00Z",
        "completed_at": "2026-07-25T00:01:00Z",
        "elapsed_seconds": 60.0,
        "checker_availability": {
            "opa": {"available": False, "message": "opa not found in PATH (optional)"}
        },
        "skipped_tests": [],
        "commands": [
            {
                "argv": ["pytest"],
                "exit_code": 0,
                "elapsed_seconds": 1.0,
            }
        ],
        "artifacts": [
            {
                "path": "ovk-evidence.json",
                "sha256": "a" * 64,
                "bytes": 12,
            }
        ],
    }
    payload.update(overrides)
    return payload


def test_validate_baseline_record_accepts_complete_payload() -> None:
    assert validate_baseline_record(_complete_baseline()) == []


def test_validate_baseline_record_rejects_missing_fields() -> None:
    payload = _complete_baseline()
    del payload["artifacts"]
    failures = validate_baseline_record(payload)
    assert failures
    assert any("artifacts" in item for item in failures)


def test_validate_baseline_record_rejects_bad_digest() -> None:
    payload = _complete_baseline(
        artifacts=[{"path": "x", "sha256": "not-a-digest"}],
    )
    failures = validate_baseline_record(payload)
    assert failures
