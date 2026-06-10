import json
from pathlib import Path

from ovk.adapters.cedar.adapter import ADAPTER as CEDAR_ADAPTER
from ovk.adapters.cedar.diff_extract import cedar_inputs_from_diff
from ovk.adapters.kani.adapter import ADAPTER as KANI_ADAPTER
from ovk.adapters.kani.diff_extract import kani_inputs_from_diff
from ovk.adapters.tla.adapter import ADAPTER as TLA_ADAPTER
from ovk.core.capabilities import CapabilityRegistry
from ovk.core.external_adapters import all_external_adapters
from ovk.core.router import route_intent
from ovk.core.surface_routing import surface_backend_bonuses


def test_wave1_adapters_implement_contract_roundtrip() -> None:
    for adapter in all_external_adapters():
        intent = {
            "intent_id": "contract-check",
            "domain": adapter.capability_manifest["supported_domains"][0],
            "property": {"kind": adapter.capability_manifest["supported_property_kinds"][0]},
        }
        score = adapter.can_handle(intent=intent, context={})
        assert score.score > 0
        obligation = adapter.compile(intent=intent, change={"input": {}, "changed_files": []})
        raw = adapter.run(obligation)
        result = adapter.normalize(raw, obligation)
        explanation = adapter.explain(result)
        assert explanation.summary
        assert result.status in {"pass", "fail", "unknown", "error", "skipped"}


def test_router_prefers_cedar_for_iam_surface() -> None:
    registry = CapabilityRegistry.from_directory(Path("adapters"))
    intent = json.loads(Path("templates/infrastructure/infra_guard_1.intent.json").read_text(encoding="utf-8"))
    bonuses = surface_backend_bonuses(["infra/iam_policy.tf"])
    decision = route_intent(intent, registry.all(), surface_bonuses=bonuses)
    assert decision["selected"][0]["backend"] == "cedar"


def test_router_prefers_tla_for_deployment_surface() -> None:
    registry = CapabilityRegistry.from_directory(Path("adapters"))
    intent = json.loads(Path("templates/deployment/no_skipped_approval_state.intent.json").read_text(encoding="utf-8"))
    bonuses = surface_backend_bonuses(["deploy/release.yml"])
    decision = route_intent(intent, registry.all(), surface_bonuses=bonuses)
    assert decision["selected"][0]["backend"] == "tla+"


def test_router_prefers_kani_for_rust_surface() -> None:
    registry = CapabilityRegistry.from_directory(Path("adapters"))
    intent = {
        "intent_id": "rust-safety-check",
        "domain": "authorization",
        "property": {"kind": "safety"},
    }
    bonuses = surface_backend_bonuses(["src/parser.rs"])
    decision = route_intent(intent, registry.all(), surface_bonuses=bonuses)
    assert decision["selected"][0]["backend"] == "kani"


def test_cedar_diff_extracts_iam_policy_input() -> None:
    diff_text = Path("examples/cedar/iam_admin_open.diff").read_text(encoding="utf-8")
    inputs = cedar_inputs_from_diff(diff_text)
    assert inputs
    evidence = CEDAR_ADAPTER.evaluate_evidence(inputs[0], repo="r", head_sha="sha")
    assert evidence.backend_claims[0].status.value == "fail"


def test_kani_diff_extracts_unsafe_rust_input() -> None:
    diff_text = Path("examples/kani/unsafe_rust.diff").read_text(encoding="utf-8")
    inputs = kani_inputs_from_diff(diff_text)
    assert inputs
    evidence = KANI_ADAPTER.evaluate_evidence(inputs[0], repo="r", head_sha="sha")
    assert evidence.backend_claims[0].status.value == "fail"


def test_tla_adapter_blocks_skipped_approval_state() -> None:
    payload = json.loads(Path("examples/backends/tla_fail.json").read_text(encoding="utf-8"))
    evidence = TLA_ADAPTER.evaluate_evidence(payload, repo="r", head_sha="sha")
    assert evidence.backend_claims[0].status.value == "fail"
