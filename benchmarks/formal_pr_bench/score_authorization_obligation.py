#!/usr/bin/env python
"""Score authorization-obligation preservation properties."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.adapters.z3.counterexample import counterexamples_from_obligation
from ovk.adapters.z3.obligation import build_authorization_obligation
from ovk.adapters.z3.regression import render_authorization_regression_suite
from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path


ROOT = Path(__file__).resolve().parents[2]


def score_fixture(path: Path, expect_counterexample: bool) -> bool:
    data = json.loads(path.read_text(encoding="utf-8"))
    obligation = build_authorization_obligation(data)
    counterexamples = counterexamples_from_obligation(obligation)
    rendered = render_authorization_regression_suite(counterexamples)
    polarity_ok = obligation.query_polarity == "find_violation"
    counterexample_ok = bool(counterexamples) is expect_counterexample
    regression_ok = ("authorization regression" in rendered) is expect_counterexample
    return polarity_ok and counterexample_ok and regression_ok


def score_malformed_fixture(path: Path) -> bool:
    data = json.loads(path.read_text(encoding="utf-8"))
    evidence = evaluate_validated_authorization_path(data, repo="benchmark/repo", head_sha="benchmark")
    status_ok = evidence.backend_claims[0].status.value == "unknown"
    decision_ok = evidence.decision["merge_recommendation"] == "require_human_review"
    diagnostic_ok = any(
        item.get("failure_mode") == "authorization_abstraction_invalid"
        for item in evidence.counterexamples
    )
    return status_ok and decision_ok and diagnostic_ok


def main() -> int:
    cases = [
        (ROOT / "examples/auth_regression/input_admin_bypass.json", True),
        (ROOT / "examples/auth_regression/input_admin_protected.json", False),
    ]
    malformed_cases = [
        ROOT / "examples/auth_regression/input_malformed_missing_routes.json",
        ROOT / "examples/auth_regression/input_malformed_bad_witness.json",
    ]
    failures = []
    for path, expect_counterexample in cases:
        ok = score_fixture(path, expect_counterexample)
        print(f"{path.name}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append(path.name)
    for path in malformed_cases:
        ok = score_malformed_fixture(path)
        print(f"{path.name}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append(path.name)
    if failures:
        print(json.dumps({"failures": failures}, indent=2))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
