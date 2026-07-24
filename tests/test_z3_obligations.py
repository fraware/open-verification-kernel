"""Tests for Z3 obligation models, fixtures, and counterexample minimization."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.adapters.z3.authorization import find_authorization_counterexamples
from ovk.adapters.z3.minimize import minimize_counterexample
from ovk.adapters.z3.privilege_escalation import (
    evaluate_privilege_escalation,
    find_privilege_escalation_counterexamples,
)
from ovk.adapters.z3.solver_authorization import evaluate_with_optional_z3
from ovk.core.counterexample_translator import repair_hint_for_counterexample


def test_admin_route_bypass_fixture_emits_counterexample() -> None:
    data = json.loads(Path("examples/z3_fail/admin_route_bypass.json").read_text(encoding="utf-8"))
    counterexamples = find_authorization_counterexamples(data)
    assert counterexamples
    assert counterexamples[0]["failure_mode"] == "admin_route_reachable_by_non_admin"
    expected = json.loads(Path("examples/z3_fail/admin_route_bypass.counterexample.json").read_text(encoding="utf-8"))
    assert counterexamples[0]["route"] == expected["route"]
    assert counterexamples[0]["user_role"] == expected["user_role"]


def test_privilege_escalation_fixture_emits_counterexample() -> None:
    data = json.loads(Path("examples/z3_fail/privilege_escalation.json").read_text(encoding="utf-8"))
    counterexamples = find_privilege_escalation_counterexamples(data)
    assert counterexamples
    assert counterexamples[0]["failure_mode"] == "privilege_escalation"
    expected = json.loads(Path("examples/z3_fail/privilege_escalation.counterexample.json").read_text(encoding="utf-8"))
    assert counterexamples[0]["principal"] == expected["principal"]
    assert counterexamples[0]["gained_role"] == expected["gained_role"]


def test_evaluate_privilege_escalation_reports_fail() -> None:
    data = json.loads(Path("examples/z3_fail/privilege_escalation.json").read_text(encoding="utf-8"))
    result = evaluate_privilege_escalation(data)
    assert result["status"] == "fail"
    assert result["counterexamples"]


def test_minimize_counterexample_trims_witness_fields() -> None:
    counterexample = {
        "summary": "Non-admin role user can reach admin-only route /admin/export.",
        "failure_mode": "admin_route_reachable_by_non_admin",
        "route": "/admin/export",
        "user_role": "user",
        "path": ["route_group_added"],
        "model": "verbose z3 model dump should be removed",
        "obligation_id": "obl-auth-admin-route-reachability",
    }
    minimized = minimize_counterexample(counterexample)
    assert minimized["minimized"] is True
    assert "model" not in minimized
    assert minimized["route"] == "/admin/export"


def test_privilege_escalation_repair_hint_fix_class() -> None:
    counterexample = json.loads(
        Path("examples/z3_fail/privilege_escalation.counterexample.json").read_text(encoding="utf-8")
    )
    hint = repair_hint_for_counterexample(counterexample)
    assert hint["fix_class"] == "revoke_privileged_grant"


def test_optional_z3_admin_route_bypass_fails() -> None:
    data = json.loads(Path("examples/z3_fail/admin_route_bypass.json").read_text(encoding="utf-8"))
    result = evaluate_with_optional_z3(data)
    assert result["status"] in {"fail", "unknown"}
