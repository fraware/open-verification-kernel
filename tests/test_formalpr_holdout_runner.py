"""Tests for FormalPR-Holdout OVK runner fail-closed guards."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from scripts.run_formalpr_holdout import (
    assert_aggregate_safe,
    extract_tarball,
    validate_aggregate_schema,
    verify_asset_sha256,
    _isolated_eval_env,
)


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


def test_validate_aggregate_schema_accepts_valid_payload() -> None:
    validate_aggregate_schema(_valid_aggregate())


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


def test_validate_aggregate_schema_rejects_missing_lane_metric() -> None:
    payload = _valid_aggregate()
    del payload["lanes"]["authorization"]["precision"]
    with pytest.raises(SystemExit, match="fail-closed"):
        validate_aggregate_schema(payload)


def test_verify_asset_sha256_accepts_and_rejects(tmp_path: Path) -> None:
    asset = tmp_path / "asset.tar.gz"
    asset.write_bytes(b"holdout-bytes")
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()
    assert verify_asset_sha256(asset, digest) == digest
    with pytest.raises(SystemExit, match="SHA-256 mismatch"):
        verify_asset_sha256(asset, "0" * 64)
    with pytest.raises(SystemExit, match="64-character"):
        verify_asset_sha256(asset, "not-a-digest")


def test_extract_tarball_rejects_symlink(tmp_path: Path) -> None:
    tarball = tmp_path / "bad.tar.gz"
    with tarfile.open(tarball, "w:gz") as tar:
        info = tarfile.TarInfo(name="root/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../outside"
        tar.addfile(info)
    with pytest.raises(SystemExit, match="link member forbidden"):
        extract_tarball(tarball, tmp_path / "out")


def test_extract_tarball_rejects_traversal(tmp_path: Path) -> None:
    tarball = tmp_path / "trav.tar.gz"
    with tarfile.open(tarball, "w:gz") as tar:
        data = b"x"
        info = tarfile.TarInfo(name="../evil.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(SystemExit, match="unsafe path|path traversal"):
        extract_tarball(tarball, tmp_path / "out")


def test_extract_tarball_accepts_regular_tree(tmp_path: Path) -> None:
    tarball = tmp_path / "good.tar.gz"
    with tarfile.open(tarball, "w:gz") as tar:
        dir_info = tarfile.TarInfo(name="release-root")
        dir_info.type = tarfile.DIRTYPE
        tar.addfile(dir_info)
        payload = b'{"ok": true}'
        file_info = tarfile.TarInfo(name="release-root/readme.json")
        file_info.size = len(payload)
        tar.addfile(file_info, io.BytesIO(payload))
    root = extract_tarball(tarball, tmp_path / "out")
    assert root.name == "release-root"
    assert (root / "readme.json").read_bytes() == payload


def test_isolated_eval_env_strips_tokens(monkeypatch) -> None:
    monkeypatch.setenv("HOLDOUT_DOWNLOAD_TOKEN", "secret-holdout")
    monkeypatch.setenv("GITHUB_TOKEN", "secret-gh")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = _isolated_eval_env()
    assert "HOLDOUT_DOWNLOAD_TOKEN" not in env
    assert "GITHUB_TOKEN" not in env
    assert env.get("PATH") == "/usr/bin"


def test_predictions_digest_rejects_embedded_labels(tmp_path: Path) -> None:
    from scripts.digest_holdout_predictions import assert_predictions_label_free, digest_predictions_file

    clean = {"predictions": [{"case_id": "case-1", "status": "fail", "merge_recommendation": "block"}]}
    assert_predictions_label_free(clean)
    path = tmp_path / "predictions.json"
    path.write_text(json.dumps(clean), encoding="utf-8")
    record = digest_predictions_file(path)
    assert record["label_free"] is True
    assert len(record["sha256"]) == 64

    dirty = {
        "predictions": [
            {
                "case_id": "case-1",
                "status": "fail",
                "expected_status": "fail",
            }
        ]
    }
    with pytest.raises(SystemExit, match="fail-closed"):
        assert_predictions_label_free(dirty)


def test_predictions_digest_rejects_forbidden_substring(tmp_path: Path) -> None:
    from scripts.digest_holdout_predictions import digest_predictions_file

    path = tmp_path / "predictions.json"
    path.write_text(
        json.dumps({"predictions": [{"case_id": "x", "note": "ground_truth_class leaked"}]}),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="fail-closed"):
        digest_predictions_file(path)


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
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    rc = runner.main(
        [
            "--artifact",
            str(artifact),
            "--asset-sha256",
            digest,
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
