"""Tests for agent repair loop fixtures and bench scoring."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.formal_pr_bench.scoring import score_repair_loop_case
from ovk.core.check import run_check


def test_ci_secrets_repair_loop_failing_diff_blocks() -> None:
    diff_text = Path("examples/repair_loops/ci_secrets/failing.diff").read_text(encoding="utf-8")
    result = run_check(diff_text=diff_text, repo="test/repo", head_sha="fail", use_cache=False)
    assert result.bundle.decision.get("merge_recommendation") == "block"
    counterexamples = [
        counterexample
        for evidence in result.bundle.evidence
        for counterexample in evidence.counterexamples
    ]
    assert counterexamples


def test_ci_secrets_repair_loop_passing_diff_allows() -> None:
    diff_text = Path("examples/repair_loops/ci_secrets/passing.diff").read_text(encoding="utf-8")
    result = run_check(diff_text=diff_text, repo="test/repo", head_sha="pass", use_cache=False)
    assert result.bundle.decision.get("merge_recommendation") == "allow"


def test_repair_loop_bench_case_scores_green() -> None:
    case = json.loads(Path("benchmarks/formal_pr_bench/extended_cases.json").read_text(encoding="utf-8"))
    ci_case = next(item for item in case["cases"] if item["case_id"] == "repair_loop_ci_secrets")
    score = score_repair_loop_case(ci_case, elapsed_ms=0.0)
    assert score.passed is True
    assert score.details["repair_loop_passed"] is True


def test_authorization_repair_loop_failing_diff_blocks() -> None:
    diff_text = Path("examples/repair_loops/authorization/failing.diff").read_text(encoding="utf-8")
    result = run_check(diff_text=diff_text, repo="test/repo", head_sha="fail", use_cache=False)
    assert result.bundle.decision.get("merge_recommendation") == "block"


def test_authorization_repair_loop_passing_diff_allows() -> None:
    diff_text = Path("examples/repair_loops/authorization/passing.diff").read_text(encoding="utf-8")
    result = run_check(diff_text=diff_text, repo="test/repo", head_sha="pass", use_cache=False)
    assert result.bundle.decision.get("merge_recommendation") == "allow"


def test_infrastructure_repair_loop_failing_diff_blocks() -> None:
    diff_text = Path("examples/repair_loops/infrastructure/failing.diff").read_text(encoding="utf-8")
    result = run_check(diff_text=diff_text, repo="test/repo", head_sha="fail", use_cache=False)
    assert result.bundle.decision.get("merge_recommendation") == "block"


def test_infrastructure_repair_loop_passing_diff_allows() -> None:
    diff_text = Path("examples/repair_loops/infrastructure/passing.diff").read_text(encoding="utf-8")
    result = run_check(diff_text=diff_text, repo="test/repo", head_sha="pass", use_cache=False)
    assert result.bundle.decision.get("merge_recommendation") == "allow"


def test_repair_loop_auth_and_infra_bench_cases_score_green() -> None:
    case = json.loads(Path("benchmarks/formal_pr_bench/extended_cases.json").read_text(encoding="utf-8"))
    for case_id in ("repair_loop_auth_bypass", "repair_loop_infra_exposure"):
        bench_case = next(item for item in case["cases"] if item["case_id"] == case_id)
        score = score_repair_loop_case(bench_case, elapsed_ms=0.0)
        assert score.passed is True, case_id
        assert score.details["repair_loop_passed"] is True
