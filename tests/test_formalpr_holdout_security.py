import io
import json
import tarfile
from pathlib import Path

import pytest

from scripts.run_formalpr_holdout import (
    assert_aggregate_safe,
    extract_tarball,
    run_harness,
    verify_asset_digest,
)


def _aggregate() -> dict:
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
                "invalid_input_rate": 0.0,
                "abstention_appropriateness": 1.0,
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


def test_asset_digest_mismatch_fails_closed(tmp_path: Path) -> None:
    artifact = tmp_path / "holdout.tar.gz"
    artifact.write_bytes(b"not-the-expected-asset")
    with pytest.raises(SystemExit, match="digest mismatch"):
        verify_asset_digest(artifact, "0" * 64)


def test_tar_path_traversal_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "malicious.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        data = b"escape"
        member = tarfile.TarInfo("../outside.txt")
        member.size = len(data)
        tar.addfile(member, io.BytesIO(data))
    with pytest.raises(SystemExit, match="unsafe archive member|escapes extraction root"):
        extract_tarball(archive, tmp_path / "extract")
    assert (tmp_path / "outside.txt").exists() is False


def test_tar_links_are_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "links.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        root = tarfile.TarInfo("release")
        root.type = tarfile.DIRTYPE
        tar.addfile(root)
        link = tarfile.TarInfo("release/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)
    with pytest.raises(SystemExit, match="forbidden special member"):
        extract_tarball(archive, tmp_path / "extract")


def test_public_aggregate_rejects_notes_and_protected_fields() -> None:
    payload = _aggregate()
    payload["reviewer_time"] = {
        "median_minutes_saved": 1.0,
        "median_minutes_added": 0.0,
        "notes": "case-level detail",
    }
    with pytest.raises(SystemExit, match="notes is not permitted"):
        assert_aggregate_safe(payload)


def test_downloaded_harness_does_not_receive_holdout_token(tmp_path: Path, monkeypatch) -> None:
    release = tmp_path / "release"
    harness = release / "harness"
    labels = release / "corpus" / "labels"
    cases = release / "corpus" / "cases"
    harness.mkdir(parents=True)
    labels.mkdir(parents=True)
    cases.mkdir(parents=True)
    output = tmp_path / "aggregate.json"
    predictions = tmp_path / "predictions.json"
    predictions.write_text(json.dumps({"predictions": []}), encoding="utf-8")
    payload = _aggregate()
    script = f"""
import argparse, json, os
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--corpus-root')
parser.add_argument('--labels-dir')
parser.add_argument('--predictions')
parser.add_argument('--holdout-release-tag')
parser.add_argument('--ovk-commit-sha')
parser.add_argument('--verified-source-sha', default=None)
parser.add_argument('--output')
args = parser.parse_args()
if os.environ.get('HOLDOUT_DOWNLOAD_TOKEN') or os.environ.get('GITHUB_TOKEN'):
    raise SystemExit(9)
Path(args.output).write_text({json.dumps(json.dumps(payload))}, encoding='utf-8')
"""
    (harness / "evaluate.py").write_text(script, encoding="utf-8")
    monkeypatch.setenv("HOLDOUT_DOWNLOAD_TOKEN", "must-not-leak")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-leak")
    result = run_harness(
        release_root=release,
        predictions=predictions,
        holdout_tag="v0.1.0-synthetic",
        ovk_sha="abc1234",
        verified_sha="abc1234",
        output=output,
    )
    assert result["cases_scored"] == 1
