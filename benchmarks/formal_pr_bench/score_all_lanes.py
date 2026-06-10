#!/usr/bin/env python
"""Score FormalPR-Bench cases and publish a multi-dimensional leaderboard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
CASES = ROOT / "benchmarks/formal_pr_bench/seed_cases.json"
CASES_EXPANDED = ROOT / "benchmarks/formal_pr_bench/seed_cases_expanded.json"
EXTENDED_CASES = ROOT / "benchmarks/formal_pr_bench/extended_cases.json"
REAL_DIFF_CASES = ROOT / "benchmarks/formal_pr_bench/real_diff_cases.json"
P95_BUDGET_MS = 5000


INTENT_TO_LANE = {
    "no-admin-route-bypass": "authorization",
    "no-public-sensitive-resource": "infrastructure",
    "no-secrets-in-untrusted-context": "ci_secrets",
    "no-skipped-approval-state": "deployment",
}


def _evaluate_lane_fixture(lane: str, fixture: str) -> dict:
    from ovk.core.multi_lane import evaluate_lane

    data = json.loads(Path(fixture).read_text(encoding="utf-8"))
    evidence = evaluate_lane(lane, data, repo="bench/repo", head_sha="seed")
    return evidence.model_dump(mode="json")


def evaluate_lane_case(case: dict) -> tuple[str, str, str | None]:
    fixture = str(ROOT / case["input_fixture"])
    intent = case["expected_intent"]

    if intent == "agent-cannot-disable-own-ci-gate":
        from ovk.adapters.opa import evaluate_self_protection

        evidence = evaluate_self_protection(json.loads(Path(fixture).read_text(encoding="utf-8")), repo="bench/repo", head_sha="seed")
        payload = evidence.model_dump(mode="json")
    elif intent in INTENT_TO_LANE:
        payload = _evaluate_lane_fixture(INTENT_TO_LANE[intent], fixture)
    elif intent in {
        "cedar-policy-check",
        "tla-state-check",
        "kani-harness-check",
        "dafny-obligation-check",
        "verus-harness-check",
        "lean-proof-check",
        "cbmc-harness-check",
        "alloy-model-check",
    }:
        from ovk.core.backend_fixture import evaluate_backend_fixture

        evidence = evaluate_backend_fixture(
            json.loads(Path(fixture).read_text(encoding="utf-8")),
            repo="bench/repo",
            head_sha="seed",
            intent_id=intent,
        )
        payload = evidence.model_dump(mode="json")
    else:
        raise ValueError(f"unsupported intent: {intent}")

    status = payload["backend_claims"][0]["status"]
    recommendation = str(payload["decision"]["merge_recommendation"])
    counterexample_class = None
    if payload.get("counterexamples"):
        counterexample_class = str(payload["counterexamples"][0].get("failure_mode"))
    return status, recommendation, counterexample_class


def load_cases(*, expanded: bool, include_extended: bool) -> tuple[list[dict[str, Any]], str]:
    cases_path = CASES_EXPANDED if expanded and CASES_EXPANDED.exists() else CASES
    data = json.loads(cases_path.read_text(encoding="utf-8"))
    cases = list(data["cases"])
    case_set = cases_path.name
    if include_extended and EXTENDED_CASES.exists():
        extended = json.loads(EXTENDED_CASES.read_text(encoding="utf-8"))
        cases.extend(extended["cases"])
        case_set = f"{case_set}+extended_cases.json"
    if include_extended and REAL_DIFF_CASES.exists():
        real_diff = json.loads(REAL_DIFF_CASES.read_text(encoding="utf-8"))
        cases.extend(real_diff["cases"])
        case_set = f"{case_set}+real_diff_cases.json"
    return cases, case_set


def run_benchmark(
    *,
    expanded: bool = False,
    include_extended: bool = True,
) -> tuple[list[Any], dict[str, Any]]:
    from ovk.core.capabilities import CapabilityRegistry

    from benchmarks.formal_pr_bench.scoring import build_leaderboard, score_case

    cases, case_set = load_cases(expanded=expanded, include_extended=include_extended)
    capabilities = CapabilityRegistry.from_directory(ROOT / "adapters").all()
    lane_evaluator: Callable[[dict[str, Any]], tuple[str, str, str | None]] = evaluate_lane_case
    scores = [
        score_case(case, capabilities=capabilities, lane_evaluator=lane_evaluator)
        for case in cases
    ]
    leaderboard = build_leaderboard(
        scores,
        benchmark_name="FormalPR-Bench",
        case_set=case_set,
    )
    return scores, leaderboard


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expanded", action="store_true", help="Score the 100-case expanded benchmark set.")
    parser.add_argument("--no-extended", action="store_true", help="Skip routing/adversarial/repair-loop cases.")
    parser.add_argument("--leaderboard", type=Path, default=None, help="Write leaderboard JSON to this path.")
    args = parser.parse_args()

    scores, leaderboard = run_benchmark(
        expanded=args.expanded,
        include_extended=not args.no_extended,
    )
    failures = [score for score in scores if not score.passed]
    for score in scores:
        print(f"{score.case_id}: {'PASS' if score.passed else 'FAIL'} ({score.elapsed_ms:.0f}ms)")
    print(f"p95_case_ms: {leaderboard['timing_ms']['p95']:.0f}")
    if not args.expanded and leaderboard["timing_ms"]["p95"] > P95_BUDGET_MS:
        failures.append(type("Failure", (), {"case_id": "timing_budget"})())

    if args.leaderboard is not None:
        args.leaderboard.parent.mkdir(parents=True, exist_ok=True)
        args.leaderboard.write_text(json.dumps(leaderboard, indent=2) + "\n", encoding="utf-8")
        print(f"leaderboard: {args.leaderboard}")

    if failures:
        print(
            json.dumps(
                {
                    "failures": [
                        {
                            "case_id": score.case_id,
                            "category": score.category,
                            "details": score.details,
                        }
                        for score in failures
                        if hasattr(score, "case_id")
                    ]
                },
                indent=2,
            )
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
