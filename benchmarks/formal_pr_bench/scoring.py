"""Multi-dimensional scoring for FormalPR-Bench."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ovk.core.capabilities import CapabilityRegistry
from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.intent_registry import IntentRegistry
from ovk.core.models import EvidenceBundle
from ovk.core.router import route_intent
from ovk.core.surface_routing import surface_backend_bonuses


ROOT = Path(__file__).resolve().parents[2]
LEADERBOARD_SCHEMA = "formal_pr_bench.leaderboard.v1"


@dataclass(frozen=True)
class DimensionScore:
    """Score for one benchmark dimension on a single case."""

    case_id: str
    category: str
    passed: bool
    merge_decision_correct: bool
    status_correct: bool
    counterexample_useful: bool | None
    backend_selection_correct: bool | None
    evidence_honest: bool | None
    elapsed_ms: float
    details: dict[str, Any]


def score_lane_case(
    case: dict[str, Any],
    *,
    status: str,
    recommendation: str,
    counterexample_class: str | None,
    elapsed_ms: float,
    capabilities: list[dict[str, Any]],
) -> DimensionScore:
    """Score a lane evaluation case across FormalPR-Bench dimensions."""
    status_ok = status == case["expected_status"]
    merge_ok = recommendation == case["expected_merge_recommendation"]
    ce_expected = case.get("expected_counterexample_class")
    ce_ok: bool | None
    if ce_expected is None:
        ce_ok = counterexample_class is None
    else:
        ce_ok = counterexample_class == ce_expected

    backend_ok: bool | None = None
    expected_backend_class = case.get("expected_backend_class")
    if expected_backend_class:
        backend_ok = status_ok or case["expected_status"] in {"pass", "fail", "unknown"}

    evidence_honest: bool | None = True if status_ok and merge_ok else False
    passed = status_ok and merge_ok and (ce_ok is not False) and evidence_honest is not False
    return DimensionScore(
        case_id=str(case["case_id"]),
        category=str(case.get("category", "lane")),
        passed=passed,
        merge_decision_correct=merge_ok,
        status_correct=status_ok,
        counterexample_useful=ce_ok,
        backend_selection_correct=backend_ok,
        evidence_honest=evidence_honest,
        elapsed_ms=elapsed_ms,
        details={
            "actual_status": status,
            "actual_recommendation": recommendation,
            "actual_counterexample_class": counterexample_class,
        },
    )


def score_routing_case(case: dict[str, Any], *, elapsed_ms: float) -> DimensionScore:
    """Score backend routing accuracy for a changed-file surface."""
    registry = CapabilityRegistry.from_directory(ROOT / "adapters")
    intent = case.get("intent")
    if intent is None:
        intents = IntentRegistry.from_directory(ROOT / "templates")
        intent = intents.get(str(case["expected_intent"]))
    if intent is None:
        raise ValueError(f"unknown intent for routing case: {case.get('expected_intent')}")
    changed_files = list(case.get("changed_files", []))
    decision = route_intent(
        intent,
        registry.all(),
        surface_bonuses=surface_backend_bonuses(changed_files),
    )
    selected = decision["selected"][0]["backend"] if decision["selected"] else None
    routing_ok = selected == case["expected_backend"]
    return DimensionScore(
        case_id=str(case["case_id"]),
        category="routing",
        passed=routing_ok,
        merge_decision_correct=routing_ok,
        status_correct=routing_ok,
        counterexample_useful=None,
        backend_selection_correct=routing_ok,
        evidence_honest=None,
        elapsed_ms=elapsed_ms,
        details={"selected_backend": selected, "expected_backend": case["expected_backend"]},
    )


def score_quality_case(case: dict[str, Any], *, elapsed_ms: float) -> DimensionScore:
    """Score evidence honesty via the quality gate on a bundle fixture."""
    bundle = EvidenceBundle.model_validate(
        json.loads((ROOT / case["input_fixture"]).read_text(encoding="utf-8"))
    )
    report = build_evidence_quality_report(bundle)
    expected_pass = bool(case.get("expected_quality_passed", False))
    honest = report.passed == expected_pass
    return DimensionScore(
        case_id=str(case["case_id"]),
        category="adversarial",
        passed=honest,
        merge_decision_correct=honest,
        status_correct=honest,
        counterexample_useful=None,
        backend_selection_correct=None,
        evidence_honest=honest,
        elapsed_ms=elapsed_ms,
        details={"quality_passed": report.passed, "expected_quality_passed": expected_pass},
    )


def score_repair_loop_case(case: dict[str, Any], *, elapsed_ms: float) -> DimensionScore:
    """Score repair-loop usefulness: block + machine-readable repair hint."""
    from ovk.core.check import run_check
    from ovk.core.counterexample_translator import repair_hint_for_counterexample

    diff_text = (ROOT / case["input_fixture"]).read_text(encoding="utf-8")
    result = run_check(diff_text=diff_text, repo="bench/repo", head_sha="seed", use_cache=False)
    recommendation = str(result.bundle.decision.get("merge_recommendation", "unknown"))
    merge_ok = recommendation == case["expected_merge_recommendation"]
    counterexamples = [
        counterexample
        for evidence in result.bundle.evidence
        for counterexample in evidence.counterexamples
    ]
    hints = [repair_hint_for_counterexample(item) for item in counterexamples]
    expected_fix = case.get("expected_fix_class")
    fix_ok = any(hint.get("fix_class") == expected_fix for hint in hints) if expected_fix else bool(counterexamples)
    repair_ok = True
    if case.get("passing_fixture"):
        passing_diff = (ROOT / case["passing_fixture"]).read_text(encoding="utf-8")
        pass_result = run_check(
            diff_text=passing_diff,
            repo="bench/repo",
            head_sha="seed-repaired",
            use_cache=False,
        )
        expected_pass = case.get("expected_pass_recommendation", "allow")
        repair_ok = str(pass_result.bundle.decision.get("merge_recommendation", "unknown")) == expected_pass
    passed = merge_ok and fix_ok and repair_ok
    return DimensionScore(
        case_id=str(case["case_id"]),
        category="repair_loop",
        passed=passed,
        merge_decision_correct=merge_ok,
        status_correct=merge_ok,
        counterexample_useful=fix_ok,
        backend_selection_correct=None,
        evidence_honest=merge_ok,
        elapsed_ms=elapsed_ms,
        details={
            "merge_recommendation": recommendation,
            "repair_hints": hints,
            "counterexample_count": len(counterexamples),
            "repair_loop_passed": repair_ok if case.get("passing_fixture") else None,
        },
    )


def score_intent_recall_case(case: dict[str, Any], *, elapsed_ms: float) -> DimensionScore:
    """Score whether the planner recalls expected intents from a diff."""
    from ovk.core.planner import plan_from_diff_text

    diff_text = (ROOT / case["input_fixture"]).read_text(encoding="utf-8")
    plan = plan_from_diff_text(diff_text)
    expected = set(case.get("expected_intents", []))
    actual = set(plan.get("candidate_intents", []))
    recall_ok = expected.issubset(actual)
    return DimensionScore(
        case_id=str(case["case_id"]),
        category="intent_recall",
        passed=recall_ok,
        merge_decision_correct=recall_ok,
        status_correct=recall_ok,
        counterexample_useful=None,
        backend_selection_correct=None,
        evidence_honest=recall_ok,
        elapsed_ms=elapsed_ms,
        details={"expected_intents": sorted(expected), "actual_intents": sorted(actual)},
    )


def score_real_diff_case(case: dict[str, Any], *, elapsed_ms: float) -> DimensionScore:
    """Score real_diff corpus cases: intent recall, lane coverage, and merge decision."""
    from ovk.core.check import run_check
    from ovk.core.planner import plan_from_diff_text

    diff_text = (ROOT / case["input_fixture"]).read_text(encoding="utf-8")
    plan = plan_from_diff_text(diff_text)
    expected_intents = set(case.get("expected_intents", []))
    actual_intents = set(plan.get("candidate_intents", []))
    intent_ok = expected_intents.issubset(actual_intents)

    result = run_check(diff_text=diff_text, repo="bench/repo", head_sha="seed", use_cache=False)
    actual_lanes = {job.get("lane") for job in result.jobs}
    expected_lanes = set(case.get("expected_lanes", []))
    lanes_ok = actual_lanes == expected_lanes

    recommendation = str(result.bundle.decision.get("merge_recommendation", "unknown"))
    merge_ok = recommendation == case["expected_merge_recommendation"]
    passed = intent_ok and lanes_ok and merge_ok
    return DimensionScore(
        case_id=str(case["case_id"]),
        category="real_diff",
        passed=passed,
        merge_decision_correct=merge_ok,
        status_correct=intent_ok and lanes_ok,
        counterexample_useful=None,
        backend_selection_correct=lanes_ok,
        evidence_honest=merge_ok,
        elapsed_ms=elapsed_ms,
        details={
            "expected_intents": sorted(expected_intents),
            "actual_intents": sorted(actual_intents),
            "expected_lanes": sorted(expected_lanes),
            "actual_lanes": sorted(actual_lanes),
            "merge_recommendation": recommendation,
        },
    )


def score_multi_backend_case(case: dict[str, Any], *, elapsed_ms: float) -> DimensionScore:
    """Score multi-lane / multi-surface PR integration cases."""
    from ovk.core.check import run_check

    diff_text = (ROOT / case["input_fixture"]).read_text(encoding="utf-8")
    result = run_check(diff_text=diff_text, repo="bench/repo", head_sha="seed", use_cache=False)
    recommendation = str(result.bundle.decision.get("merge_recommendation", "unknown"))
    merge_ok = recommendation == case["expected_merge_recommendation"]
    lane_count = len(result.bundle.evidence)
    min_lanes = int(case.get("expected_lane_count_min", 2))
    lanes_ok = lane_count >= min_lanes
    passed = merge_ok and lanes_ok
    return DimensionScore(
        case_id=str(case["case_id"]),
        category="multi_backend",
        passed=passed,
        merge_decision_correct=merge_ok,
        status_correct=lanes_ok,
        counterexample_useful=None,
        backend_selection_correct=lanes_ok,
        evidence_honest=merge_ok,
        elapsed_ms=elapsed_ms,
        details={"lane_count": lane_count, "merge_recommendation": recommendation},
    )


def score_case(
    case: dict[str, Any],
    *,
    capabilities: list[dict[str, Any]] | None = None,
    lane_evaluator: Any | None = None,
) -> DimensionScore:
    """Dispatch scoring for any FormalPR-Bench case category."""
    category = str(case.get("category", "lane"))
    started = time.perf_counter()

    if category == "routing":
        elapsed_ms = (time.perf_counter() - started) * 1000
        return score_routing_case(case, elapsed_ms=elapsed_ms)

    if category == "adversarial":
        elapsed_ms = (time.perf_counter() - started) * 1000
        return score_quality_case(case, elapsed_ms=elapsed_ms)

    if category == "repair_loop":
        score = score_repair_loop_case(case, elapsed_ms=0.0)
        return DimensionScore(**{**asdict(score), "elapsed_ms": (time.perf_counter() - started) * 1000})

    if category == "multi_backend":
        score = score_multi_backend_case(case, elapsed_ms=0.0)
        return DimensionScore(**{**asdict(score), "elapsed_ms": (time.perf_counter() - started) * 1000})

    if category == "intent_recall":
        elapsed_ms = (time.perf_counter() - started) * 1000
        return score_intent_recall_case(case, elapsed_ms=elapsed_ms)

    if category == "real_diff":
        score = score_real_diff_case(case, elapsed_ms=0.0)
        return DimensionScore(**{**asdict(score), "elapsed_ms": (time.perf_counter() - started) * 1000})

    if lane_evaluator is None:
        raise ValueError("lane_evaluator is required for lane cases")
    status, recommendation, counterexample_class = lane_evaluator(case)
    elapsed_ms = (time.perf_counter() - started) * 1000
    return score_lane_case(
        case,
        status=status,
        recommendation=recommendation,
        counterexample_class=counterexample_class,
        elapsed_ms=elapsed_ms,
        capabilities=capabilities or [],
    )


def aggregate_dimensions(scores: list[DimensionScore]) -> dict[str, Any]:
    """Aggregate per-dimension pass rates for leaderboard publication."""
    if not scores:
        return {}
    total = len(scores)

    def _rate(values: list[bool | None]) -> float | None:
        present = [value for value in values if value is not None]
        if not present:
            return None
        return sum(1 for value in present if value) / len(present)

    by_category: dict[str, list[DimensionScore]] = {}
    for score in scores:
        by_category.setdefault(score.category, []).append(score)

    return {
        "cases_total": total,
        "cases_passed": sum(1 for score in scores if score.passed),
        "merge_decision_accuracy": _rate([score.merge_decision_correct for score in scores]),
        "status_accuracy": _rate([score.status_correct for score in scores]),
        "counterexample_usefulness": _rate([score.counterexample_useful for score in scores]),
        "backend_selection_accuracy": _rate([score.backend_selection_correct for score in scores]),
        "evidence_honesty": _rate([score.evidence_honest for score in scores]),
        "intent_recall": _rate([score.status_correct for score in scores if score.category == "intent_recall"]),
        "real_diff_recall": _rate([score.status_correct for score in scores if score.category == "real_diff"]),
        "real_diff_intent_recall": _rate(
            [score.status_correct for score in scores if score.category == "real_diff"]
        ),
        "by_category": {
            category: {
                "cases_total": len(items),
                "cases_passed": sum(1 for item in items if item.passed),
                "pass_rate": sum(1 for item in items if item.passed) / len(items),
            }
            for category, items in sorted(by_category.items())
        },
    }


def build_leaderboard(
    scores: list[DimensionScore],
    *,
    benchmark_name: str,
    case_set: str,
) -> dict[str, Any]:
    """Build a publishable leaderboard JSON artifact."""
    timings = sorted(score.elapsed_ms for score in scores)
    p50_index = max(0, len(timings) // 2 - 1)
    p95_index = max(0, int(len(timings) * 0.95) - 1)
    return {
        "schema_version": LEADERBOARD_SCHEMA,
        "benchmark": benchmark_name,
        "case_set": case_set,
        "generated_at_unix_ms": int(time.time() * 1000),
        "summary": aggregate_dimensions(scores),
        "timing_ms": {
            "p50": timings[p50_index] if timings else 0.0,
            "p95": timings[p95_index] if timings else 0.0,
            "max": timings[-1] if timings else 0.0,
        },
        "cases": [asdict(score) for score in scores],
    }
