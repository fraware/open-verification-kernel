import json
from pathlib import Path

from ovk.adapters.z3.counterexample import counterexamples_from_obligation
from ovk.adapters.z3.obligation import build_authorization_obligation, obligation_to_dict
from ovk.adapters.z3.smt_plan import build_smt_plan, smt_plan_to_dict


def load_fixture(name: str) -> dict:
    return json.loads(Path(f"examples/auth_regression/{name}").read_text(encoding="utf-8"))


def test_authorization_obligation_records_query_polarity() -> None:
    obligation = build_authorization_obligation(load_fixture("input_admin_bypass.json"))
    assert obligation.intent_id == "no-admin-route-bypass"
    assert obligation.query_polarity == "find_violation"
    assert obligation.routes[0].path == "/admin/export"


def test_obligation_serialization_contains_reachability_witness() -> None:
    obligation = build_authorization_obligation(load_fixture("input_admin_bypass.json"))
    payload = obligation_to_dict(obligation)
    assert payload["query_polarity"] == "find_violation"
    assert payload["routes"][0]["reachable_after"][0]["role"] == "user"


def test_counterexample_translation_preserves_obligation_metadata() -> None:
    obligation = build_authorization_obligation(load_fixture("input_admin_bypass.json"))
    counterexamples = counterexamples_from_obligation(obligation)
    assert len(counterexamples) == 1
    assert counterexamples[0]["obligation_id"] == obligation.obligation_id
    assert counterexamples[0]["query_polarity"] == "find_violation"


def test_smt_plan_contains_violation_clause() -> None:
    obligation = build_authorization_obligation(load_fixture("input_admin_bypass.json"))
    plan = build_smt_plan(obligation)
    payload = smt_plan_to_dict(plan)
    assert payload["obligation_id"] == obligation.obligation_id
    assert payload["query_polarity"] == "find_violation"
    assert len(payload["clauses"]) == 1
    assert "reachable_after" in payload["clauses"][0]["expression"]


def test_smt_plan_has_no_clauses_for_protected_admin_only_access() -> None:
    obligation = build_authorization_obligation(load_fixture("input_admin_protected.json"))
    plan = build_smt_plan(obligation)
    assert smt_plan_to_dict(plan)["clauses"] == []
