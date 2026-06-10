import json
from pathlib import Path

from ovk.adapters.alloy.evidence import evaluate_alloy_model
from ovk.adapters.cbmc.evidence import evaluate_cbmc_harness
from ovk.adapters.dafny.evidence import evaluate_dafny_obligation
from ovk.adapters.lean.evidence import evaluate_lean_obligation
from ovk.adapters.verus.evidence import evaluate_verus_harness
from ovk.core.capabilities import CapabilityRegistry
from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.external_adapters import all_external_adapters
from ovk.core.models import EvidenceBundle
from ovk.core.router import route_intent
from ovk.core.surface_routing import surface_backend_bonuses
from ovk.core.templates_cli import list_templates


def test_wave2_adapters_implement_contract_roundtrip() -> None:
    wave2 = {"dafny", "verus", "lean", "cbmc", "alloy"}
    adapters = [adapter for adapter in all_external_adapters() if adapter.backend_name in wave2]
    assert len(adapters) == 5
    for adapter in adapters:
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


def test_wave2_backend_pass_and_fail() -> None:
    cases = [
        (evaluate_dafny_obligation, "dafny_pass.json", "dafny_fail.json"),
        (evaluate_verus_harness, "verus_pass.json", "verus_fail.json"),
        (evaluate_lean_obligation, "lean_pass.json", "lean_fail.json"),
        (evaluate_cbmc_harness, "cbmc_pass.json", "cbmc_fail.json"),
        (evaluate_alloy_model, "alloy_pass.json", "alloy_fail.json"),
    ]
    for evaluator, pass_fixture, fail_fixture in cases:
        passed = evaluator(
            json.loads(Path(f"examples/backends/{pass_fixture}").read_text(encoding="utf-8")),
            repo="r",
            head_sha="sha",
        )
        failed = evaluator(
            json.loads(Path(f"examples/backends/{fail_fixture}").read_text(encoding="utf-8")),
            repo="r",
            head_sha="sha",
        )
        assert passed.backend_claims[0].status.value == "pass"
        assert failed.backend_claims[0].status.value == "fail"


def test_router_prefers_wave2_surface_backends() -> None:
    registry = CapabilityRegistry.from_directory(Path("adapters"))
    routing_cases = [
        ("templates/authorization/route_guard_6.intent.json", ["src/proof.dfy"], "dafny"),
        (
            {
                "intent_id": "verus-safety-check",
                "domain": "authorization",
                "property": {"kind": "safety"},
            },
            ["src/verus/parser.rs"],
            "verus",
        ),
        ("templates/agent_authority/agent_guard_5.intent.json", ["proofs/boundary.lean"], "lean"),
        (
            {
                "intent_id": "cbmc-safety-check",
                "domain": "infrastructure",
                "property": {"kind": "safety"},
            },
            ["drivers/buffer.c"],
            "cbmc",
        ),
        ("templates/deployment/deploy_guard_3.intent.json", ["models/deploy.als"], "alloy"),
    ]
    for intent_source, files, expected_backend in routing_cases:
        intent = (
            intent_source
            if isinstance(intent_source, dict)
            else json.loads(Path(intent_source).read_text(encoding="utf-8"))
        )
        bonuses = surface_backend_bonuses(files)
        decision = route_intent(intent, registry.all(), surface_bonuses=bonuses)
        assert decision["selected"][0]["backend"] == expected_backend


def test_template_library_has_fifty_plus_templates() -> None:
    templates = list_templates()
    assert len(templates) >= 50


def test_capability_registry_lists_ten_backends() -> None:
    registry = CapabilityRegistry.from_directory(Path("adapters"))
    tools = {manifest.get("tool", {}).get("name") for manifest in registry.all()}
    for backend in ["opa", "z3", "cedar", "tla+", "kani", "dafny", "verus", "lean", "cbmc", "alloy"]:
        assert backend in tools


def test_inv_005_blocks_inferred_high_risk_allow_without_provenance() -> None:
    bundle = EvidenceBundle.model_validate(
        {
            "bundle_id": "bundle-test",
            "subject": {"repo": "r", "head_sha": "sha"},
            "decision": {"merge_recommendation": "allow"},
            "evidence": [
                {
                    "evidence_id": "evidence-test",
                    "subject": {"repo": "r", "head_sha": "sha"},
                    "intent": {
                        "intent_id": "inferred-high-risk",
                        "risk": {"severity": "high"},
                        "provenance": {"inferred": True, "source": "planner"},
                    },
                    "backend_claims": [
                        {
                            "backend": "opa",
                            "guarantee_type": "policy_evaluation",
                            "status": "pass",
                            "assumptions": ["test"],
                            "limits": ["test"],
                            "adapter_version": "0.1.0",
                        }
                    ],
                    "decision": {"merge_recommendation": "allow", "human_review_required": False},
                    "generated_artifacts": [{"kind": "input_digest", "digest": "abc"}],
                }
            ],
        }
    )
    report = build_evidence_quality_report(bundle)
    assert not report.passed
    assert any("OVK-INV-005" in issue.message for issue in report.issues)
