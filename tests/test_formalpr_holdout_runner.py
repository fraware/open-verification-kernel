"""Tests for FormalPR-Holdout OVK runner fail-closed guards."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.run_formalpr_holdout import assert_aggregate_safe


def _valid_aggregate() -> dict:
    return {
        "schema_version": "formalpr_holdout.aggregate_metrics.v1",
        "benchmark": "FormalPR-Holdout",
        "holdout_release_tag": "v0.1.0-synthetic",
        "ovk_commit_sha": "abc1234",
        "verified_source_sha": "abc1234",
        "generated_at_unix_ms": 1,
        "cases_scored": 1,
        "lanes": {
            "authorization": {
                "cases": 1,
                "precision": 1.0,
                "recall": 1.0,
                "false_positive_rate": 0.0,
                "missed_detection_rate": 0.0,
                "unknown_rate": 0.0,
                "invalid_input_rate": None,
                "abstention_appropriateness": None,
                "coverage_completeness": 1.0,
                "counterexample_correctness": 1.0,
                "selected_backend_execution_correctness": 1.0,
                "runtime_ms": {"median": 1.0, "p95": 1.0, "max": 1.0},
            }
        },
        "disagreement_summary": {"open": 0, "resolved": 0, "deferred": 0, "total": 0},
        "leakage_guard": {
            "labels_emitted": False,
            "case_ids_emitted": False,
            "fail_closed": True,
            "sanitizer_version": "formalpr_holdout.sanitizer.v1",
        },
    }


def test_assert_aggregate_safe_accepts_valid_payload() -> None:
    assert_aggregate_safe(_valid_aggregate())


def test_assert_aggregate_safe_rejects_case_id_leak() -> None:
    payload = _valid_aggregate()
    payload["notes"] = "syn-auth-bypass-01"
    with pytest.raises(SystemExit, match="fail-closed"):
        assert_aggregate_safe(payload)


def test_assert_aggregate_safe_rejects_label_flag() -> None:
    payload = _valid_aggregate()
    payload["leakage_guard"]["labels_emitted"] = True
    with pytest.raises(SystemExit, match="fail-closed"):
        assert_aggregate_safe(payload)


def test_run_formalpr_holdout_against_local_artifact(tmp_path: Path) -> None:
    """End-to-end against a sibling-packaged release if present."""
    holdout_root = Path(__file__).resolve().parents[1].parent / "FormalPR-Holdout"
    artifact = holdout_root / "releases" / "FormalPR-Holdout-v0.1.0-synthetic.tar.gz"
    labels = holdout_root / "corpus" / "labels"
    if not artifact.is_file() or not labels.is_dir():
        pytest.skip("local FormalPR-Holdout release artifact not available")

    from scripts import run_formalpr_holdout as runner

    # Build perfect predictions without importing holdout labels into assertions output.
    preds = {"predictions": []}
    for path in sorted(labels.glob("*.json")):
        label = json.loads(path.read_text(encoding="utf-8"))
        preds["predictions"].append(
            {
                "case_id": label["case_id"],
                "status": label["expected_status"],
                "merge_recommendation": label["expected_merge_recommendation"],
                "counterexample_class": label.get("expected_counterexample_class"),
                "backend_class": label.get("expected_backend_class"),
                "backend_execution_ok": True if label.get("expected_backend_class") else None,
                "coverage_completeness": 1.0,
                "elapsed_ms": 5.0,
                "counterexample_checks": {
                    "refers_to_changed_material": True,
                    "witness_feasible": True,
                    "source_locations_accurate": True,
                    "failure_mode_matches_property": True,
                    "independently_reproducible": True,
                },
            }
        )
    pred_path = tmp_path / "predictions.json"
    pred_path.write_text(json.dumps(preds), encoding="utf-8")
    out = tmp_path / "agg.json"
    rc = runner.main(
        [
            "--artifact",
            str(artifact),
            "--tag",
            "v0.1.0-synthetic",
            "--predictions",
            str(pred_path),
            "--ovk-commit-sha",
            "abc1234",
            "--output",
            str(out),
        ]
    )
    assert rc == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["cases_scored"] == 7
    assert "lanes" in payload
    assert "syn-auth-bypass-01" not in out.read_text(encoding="utf-8")
