"""Tests for BackendRegistry and lane evaluator wrappers."""

from __future__ import annotations

import pytest

from ovk.adapters.lane import (
    AUTHORIZATION_LANE_ADAPTER,
    LANE_ADAPTERS,
    SELF_PROTECTION_LANE_ADAPTER,
    build_default_lane_registry,
)
from ovk.adapters.lane.authorization_adapter import AuthorizationLaneAdapter
from ovk.core.backend_registry import BackendRegistry, BackendRegistryError
from ovk.core.execution_models import (
    AbstractionCoverage,
    BackendCapabilityManifest,
    BackendGuaranteeDeclaration,
    BackendSelection,
    BackendToolIdentity,
    ExecutionBudget,
    ExecutionContext,
    FallbackPolicy,
    MaterialReference,
    RoutingDecision,
    VerificationObligation,
    compute_abstraction_digest,
    compute_obligation_id,
    compute_routing_id,
)
from ovk.core.models import RiskSeverity, VerificationStatus, VerificationSubject


def _subject() -> VerificationSubject:
    return VerificationSubject(repo="example/repo", head_sha="abc123", base_sha="def456")


def _budget() -> ExecutionBudget:
    return ExecutionBudget(
        total_wall_time_seconds=60.0,
        per_backend_wall_time_seconds=30.0,
        max_memory_mb=512,
        max_parallel_backends=2,
        allow_network=False,
        allow_repository_write=False,
    )


def _obligation(*, lane: str = "authorization", property_kind: str = "access_control") -> VerificationObligation:
    provisional = VerificationObligation(
        obligation_id="pending",
        subject=_subject(),
        intent_id="no-admin-route-bypass",
        intent_version="0.1.0",
        lane=lane,
        property_kind=property_kind,
        severity=RiskSeverity.HIGH,
        compiler_id="test-compiler",
        compiler_version="0.1.0",
        materials=[
            MaterialReference(
                material_id="mat-1",
                kind="diff",
                uri="src/routes.py",
                sha256="a" * 64,
                size_bytes=10,
            )
        ],
        abstraction={
            "author_type": "ai_agent",
            "agent": "codex",
            "task": "test",
            "routes": [
                {
                    "path": "/admin/export",
                    "admin_only_before": True,
                    "admin_only_after": True,
                    "reachable_after": [
                        {
                            "role": "user",
                            "via": ["middleware_not_applied", "handler_reachable"],
                        }
                    ],
                }
            ],
        },
        abstraction_digest="pending",
        coverage=AbstractionCoverage(
            status="complete",
            confidence=1.0,
            extracted_elements=1,
            expected_elements=1,
        ),
        acceptable_guarantees=["smt_refutation_search", "deterministic_witness"],
        required_capabilities=["authorization"],
        policy_digest="policy-1",
    )
    abs_digest = compute_abstraction_digest(provisional.abstraction)
    provisional = provisional.model_copy(update={"abstraction_digest": abs_digest})
    return provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})


def _routing(obligation: VerificationObligation, backend: str) -> RoutingDecision:
    budget = _budget()
    fallback = FallbackPolicy(allow_fallback=False)
    selected = [
        BackendSelection(
            backend=backend,
            reason="test",
            expected_guarantee="smt_refutation_search",
            required=True,
            score=1.0,
        )
    ]
    routing_id = compute_routing_id(
        obligation_id=obligation.obligation_id,
        requested=[backend],
        eligible=[{"backend": backend, "score": 1.0, "support": "supported", "guarantee_type": "smt"}],
        selected=selected,
        rejected=[],
        aggregation_policy="ovk.aggregate.fail_dominant.v1",
        fallback_policy=fallback,
        budget=budget,
        policy_digest=obligation.policy_digest,
        router_version="test",
    )
    return RoutingDecision(
        routing_id=routing_id,
        obligation_id=obligation.obligation_id,
        requested=[backend],
        eligible=[],
        selected=selected,
        rejected=[],
        aggregation_policy="ovk.aggregate.fail_dominant.v1",
        fallback_policy=fallback,
        budget=budget,
        policy_digest=obligation.policy_digest,
    )


def test_default_lane_registry_registers_five_unique_backends() -> None:
    registry = build_default_lane_registry()
    ids = registry.backend_ids()
    assert len(ids) == 5
    assert len(set(ids)) == 5
    assert ids == tuple(adapter.backend_id for adapter in LANE_ADAPTERS)


def test_registry_rejects_duplicate_backend_id() -> None:
    registry = BackendRegistry()
    registry.register(SELF_PROTECTION_LANE_ADAPTER)
    with pytest.raises(BackendRegistryError, match="duplicate backend"):
        registry.register(SELF_PROTECTION_LANE_ADAPTER)


def test_registry_rejects_duplicate_adapter_identity() -> None:
    class Clone(AuthorizationLaneAdapter):
        backend_id = "lane-authorization-clone"

    registry = BackendRegistry()
    registry.register(AUTHORIZATION_LANE_ADAPTER)
    with pytest.raises(BackendRegistryError, match="duplicate adapter identity"):
        registry.register(Clone())


def test_registry_require_missing_adapter() -> None:
    registry = BackendRegistry()
    assert registry.get("missing") is None
    with pytest.raises(BackendRegistryError, match="not registered"):
        registry.require("missing")


def test_candidates_deterministic_ordering_and_lane_assessment() -> None:
    registry = build_default_lane_registry()
    obligation = _obligation(lane="authorization", property_kind="access_control")
    context = ExecutionContext(subject=_subject(), budget=_budget())
    first = registry.candidates(obligation, context)
    second = registry.candidates(obligation, context)
    assert [item.backend for item in first] == [item.backend for item in second]
    auth = next(item for item in first if item.backend == "lane-authorization")
    assert auth.support == "supported"
    assert auth.score > 0
    others = [item for item in first if item.backend != "lane-authorization"]
    assert all(item.support == "unsupported" or item.score < auth.score for item in others)
    # Descending score order
    scores = [item.score for item in first]
    assert scores == sorted(scores, reverse=True)


def test_lane_adapter_compile_run_normalize_pass_fail_unknown() -> None:
    adapter = AUTHORIZATION_LANE_ADAPTER
    obligation = _obligation()
    routing = _routing(obligation, adapter.backend_id)
    compiled = adapter.compile(obligation, routing)
    assert compiled.backend == adapter.backend_id
    assert compiled.payload_digest
    assert compiled.backend_obligation_id != "pending"

    fingerprint = adapter.fingerprint(compiled)
    assert fingerprint.backend == adapter.backend_id
    assert fingerprint.environment_digest

    raw = adapter.run(compiled, _budget())
    assert raw.termination in {"completed", "timeout", "tool_error"}
    normalized = adapter.normalize(raw, compiled)
    assert normalized.status in {
        VerificationStatus.PASS,
        VerificationStatus.FAIL,
        VerificationStatus.UNKNOWN,
        VerificationStatus.ERROR,
    }
    explanation = adapter.explain(normalized)
    assert explanation.summary


def test_lane_adapter_malformed_authorization_yields_non_pass() -> None:
    adapter = AUTHORIZATION_LANE_ADAPTER
    obligation = _obligation()
    obligation = obligation.model_copy(update={"abstraction": {"routes": "not-a-list"}})
    routing = _routing(obligation, adapter.backend_id)
    compiled = adapter.compile(obligation, routing)
    raw = adapter.run(compiled, _budget())
    normalized = adapter.normalize(raw, compiled)
    assert normalized.status != VerificationStatus.PASS


def test_capability_manifest_schema_validation_on_register() -> None:
    class Broken:
        backend_id = "broken"
        adapter_id = "broken-adapter"
        adapter_version = "0.1.0"

        def manifest(self) -> BackendCapabilityManifest:
            return BackendCapabilityManifest(
                capability_id="broken",
                tool=BackendToolIdentity(
                    name="broken",
                    adapter="wrong-adapter",
                    adapter_version="0.1.0",
                ),
                backend_class="custom",
                guarantee=BackendGuaranteeDeclaration(
                    type="x",
                    meaning_of_pass="p",
                    meaning_of_fail="f",
                    meaning_of_unknown="u",
                ),
                supported_domains=["authorization"],
                supported_property_kinds=["access_control"],
            )

        def can_handle(self, obligation, context):  # noqa: ANN001
            raise NotImplementedError

        def compile(self, obligation, routing):  # noqa: ANN001
            raise NotImplementedError

        def fingerprint(self, backend_obligation):  # noqa: ANN001
            raise NotImplementedError

        def run(self, backend_obligation, budget):  # noqa: ANN001
            raise NotImplementedError

        def normalize(self, raw, backend_obligation):  # noqa: ANN001
            raise NotImplementedError

        def explain(self, result):  # noqa: ANN001
            raise NotImplementedError

    registry = BackendRegistry()
    with pytest.raises(BackendRegistryError, match="tool.adapter"):
        registry.register(Broken())  # type: ignore[arg-type]


def test_budget_denylist_marks_unavailable() -> None:
    registry = build_default_lane_registry()
    obligation = _obligation()
    budget = _budget().model_copy(update={"denied_backends": ["lane-authorization"]})
    context = ExecutionContext(subject=_subject(), budget=budget)
    assessments = registry.candidates(obligation, context)
    auth = next(item for item in assessments if item.backend == "lane-authorization")
    assert auth.support == "unavailable"
    assert auth.score < 0
