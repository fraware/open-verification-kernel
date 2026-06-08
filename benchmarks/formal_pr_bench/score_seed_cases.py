#!/usr/bin/env python
"""Score the initial FormalPR-Bench seed cases."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.adapters.opa import evaluate_self_protection
from ovk.adapters.z3 import evaluate_authorization_reachability


ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "benchmarks/formal_pr_bench/seed_cases.json"


def evaluate_case(case: dict) -> tuple[str, str, str | None]:
    fixture = json.loads((ROOT / case["input_fixture"]).read_text(encoding="utf-8"))
    if case["expected_intent"] == "agent-cannot-disable-own-ci-gate":
        evidence = evaluate_self_protection(fixture, repo="bench/repo", head_sha="seed")
    elif case["expected_intent"] == "no-admin-route-bypass":
        evidence = evaluate_authorization_reachability(fixture, repo="bench/repo", head_sha="seed")
    else:
        raise ValueError(f"unsupported intent: {case['expected_intent']}")

    status = evidence.backend_claims[0].status.value
    recommendation = str(evidence.decision["merge_recommendation"])
    counterexample_class = None
    if evidence.counterexamples:
        counterexample_class = str(evidence.counterexamples[0].get("failure_mode"))
    return status, recommendation, counterexample_class


def main() -> int:
    data = json.loads(CASES.read_text(encoding="utf-8"))
    failures = []
    for case in data["cases"]:
        status, recommendation, counterexample_class = evaluate_case(case)
        ok = (
            status == case["expected_status"]
            and recommendation == case["expected_merge_recommendation"]
            and counterexample_class == case["expected_counterexample_class"]
        )
        print(f"{case['case_id']}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append(
                {
                    "case_id": case["case_id"],
                    "actual": [status, recommendation, counterexample_class],
                    "expected": [
                        case["expected_status"],
                        case["expected_merge_recommendation"],
                        case["expected_counterexample_class"],
                    ],
                }
            )
    if failures:
        print(json.dumps({"failures": failures}, indent=2))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
