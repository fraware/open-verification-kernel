"""Integration tests for benchmarks/real_diffs corpus."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.core.check import run_check


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "benchmarks/real_diffs/manifest.json"
DIFF_ROOT = ROOT / "benchmarks/real_diffs"


def _manifest_cases() -> list[dict]:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return list(payload["cases"])


@pytest.mark.parametrize("case", _manifest_cases(), ids=lambda case: case["case_id"])
def test_real_diff_ovk_check_matches_manifest(case: dict) -> None:
    diff_path = DIFF_ROOT / case["diff"]
    diff_text = diff_path.read_text(encoding="utf-8")
    result = run_check(diff_text=diff_text, use_cache=False, repo="bench/repo", head_sha="seed")

    actual_lanes = sorted({job.get("lane") for job in result.jobs})
    assert actual_lanes == sorted(case["expected_lanes"])

    recommendation = result.bundle.decision.get("merge_recommendation")
    assert recommendation == case["expected_recommendation"]

    actual_intents = result.plan.get("candidate_intents", [])
    for intent_id in case.get("expected_intents", []):
        assert intent_id in actual_intents


def test_real_diff_manifest_has_target_corpus_size() -> None:
    cases = _manifest_cases()
    assert 10 <= len(cases) <= 20


def test_real_diff_intent_recall_at_least_ninety_five_percent() -> None:
    cases = _manifest_cases()
    recalled = 0
    for case in cases:
        diff_text = (DIFF_ROOT / case["diff"]).read_text(encoding="utf-8")
        plan = run_check(diff_text=diff_text, use_cache=False, repo="bench/repo", head_sha="seed").plan
        expected = set(case.get("expected_intents", []))
        actual = set(plan.get("candidate_intents", []))
        if expected.issubset(actual):
            recalled += 1
    recall = recalled / len(cases)
    assert recall >= 0.95, f"intent recall {recall:.1%} below 95% target"
