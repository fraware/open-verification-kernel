"""WP-13/14 holdout predict/eval separation and consumer SHA pin rules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.digest_holdout_predictions import (
    assert_predictions_label_free,
    build_predictions_from_case_manifest,
)

REPO = Path(__file__).resolve().parents[1]


def test_build_predictions_are_label_free_and_candidate_only(tmp_path: Path) -> None:
    manifest = REPO / "benchmarks" / "formal_pr_bench" / "holdout_case_manifest.labels_free.json"
    payload = build_predictions_from_case_manifest(
        case_manifest=manifest,
        candidate_source_sha="a" * 40,
    )
    assert_predictions_label_free(payload)
    assert payload["candidate_source_sha"] == "a" * 40
    assert "verified_source_sha" not in payload
    assert payload["label_free"] is True
    assert len(payload["cases"]) >= 1
    # Real predictor path: synthetic cases must not all be placeholder unknown.
    preds = {item["prediction"] for item in payload["cases"]}
    assert preds != {"unknown"}
    assert all(item.get("predictor") == "ovk.holdout.labels_free.v1" for item in payload["cases"])


def test_holdout_eval_workflow_omits_verified_source_sha() -> None:
    text = (REPO / ".github" / "workflows" / "holdout-eval.yml").read_text(encoding="utf-8")
    assert "--verified-source-sha" not in text
    assert "candidate_source_sha" in text
    assert "verified_source_sha" in text  # mentioned as forbidden in comments/asserts


def test_holdout_predict_workflow_exists() -> None:
    path = REPO / ".github" / "workflows" / "holdout-predict.yml"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "HOLDOUT_DOWNLOAD_TOKEN" in text
    assert "verified_source_sha" in text  # refused
    assert "candidate-source-sha" in text


def test_dogfood_regression_renamed() -> None:
    dogfood = REPO / ".github" / "workflows" / "dogfood-regression.yml"
    assert dogfood.is_file()
    assert "Dogfood Regression" in dogfood.read_text(encoding="utf-8")
    legacy = (REPO / ".github" / "workflows" / "external-validation.yml").read_text(encoding="utf-8")
    assert "dogfood" in legacy.lower() or "Renamed" in legacy


def test_consumer_pin_requires_40_hex_not_tag() -> None:
    text = (REPO / ".github" / "workflows" / "consumer-pin-verification.yml").read_text(encoding="utf-8")
    assert "ovk_candidate_sha" in text
    assert "default: v1.2.1" not in text
    assert "[0-9a-f]{40}" in text
    assert "forbidden uses: ./" in text
