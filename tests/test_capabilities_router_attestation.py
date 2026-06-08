import json
from pathlib import Path

from ovk.adapters.opa import evaluate_self_protection
from ovk.core.attestation import PREDICATE_TYPE, bundle_to_statement
from ovk.core.bundle import make_bundle
from ovk.core.capabilities import CapabilityRegistry
from ovk.core.router import route_intent


def test_capability_registry_loads_manifests() -> None:
    registry = CapabilityRegistry.from_directory(Path("adapters"))
    tools = {manifest["tool"]["name"] for manifest in registry.all()}
    assert "opa" in tools
    assert "z3" in tools


def test_router_selects_opa_for_ci_invariant() -> None:
    registry = CapabilityRegistry.from_directory(Path("adapters"))
    intent = json.loads(Path("templates/ci_cd/agent_cannot_disable_own_gate.intent.json").read_text())
    plan = route_intent(intent, registry.all())
    selected = {item["backend"] for item in plan["selected"]}
    assert "opa" in selected


def test_attestation_statement_contains_predicate_type() -> None:
    data = json.loads(Path("examples/no_agent_self_approval/input_gate_removed.json").read_text())
    evidence = evaluate_self_protection(data, repo="example/repo", head_sha="abc")
    bundle = make_bundle([evidence])
    statement = bundle_to_statement(bundle)
    assert statement["predicateType"] == PREDICATE_TYPE
    assert statement["subject"][0]["digest"]["gitCommit"] == "abc"
