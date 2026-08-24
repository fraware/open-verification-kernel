"""Convert control-plane execution records into VerificationEvidence."""

from __future__ import annotations

from typing import Any

from ovk.compilers.authorization import CoveragePolicy, strict_allow_permitted
from ovk.core.bundle import content_digest
from ovk.core.execution_models import ObligationExecutionRecord
from ovk.core.materials import material_set_digest_for_obligation
from ovk.core.models import BackendClaim, DecisionState, MergeRecommendation, VerificationEvidence, VerificationStatus
from ovk.core.router import ROUTER_VERSION


def execution_record_to_evidence(
    record: ObligationExecutionRecord,
    *,
    author_type: str = "unknown",
    agent: str = "unknown",
    task: str = "unknown",
    routing_enforced: bool = False,
    schema_version: str = "ovk.evidence.v2",
    coverage_policy: CoveragePolicy | None = None,
) -> VerificationEvidence:
    """Project an obligation execution record into public evidence.

    Evidence v3 carries the complete typed control-plane trace required to
    independently recompute the obligation, route, backend-obligation, attempt,
    material-set and aggregate-decision identities. The trace is included in the
    evidence digest and therefore cannot be substituted after sealing.
    """
    obligation = record.obligation
    routing = record.routing

    counterexamples: list[dict[str, Any]] = []
    for result in record.results:
        counterexamples.extend(result.counterexamples)

    required_by_backend = {item.backend: bool(item.required) for item in routing.selected}
    attempt_by_backend = {item.backend: item for item in record.attempts}
    claims = [
        BackendClaim(
            backend=result.backend,
            guarantee_type=result.guarantee_type,
            status=result.status,
            assumptions=list(result.assumptions),
            limits=list(result.limits),
            tool_version=(attempt_by_backend.get(result.backend).tool_version if attempt_by_backend.get(result.backend) else None),
            adapter_version=next(
                (item.adapter_version for item in record.backend_obligations if item.backend == result.backend),
                None,
            ),
            required=required_by_backend.get(result.backend, True),
        )
        for result in sorted(record.results, key=lambda item: item.backend)
    ]

    if not claims:
        claims = [
            BackendClaim(
                backend="none",
                guarantee_type="none",
                status=VerificationStatus.UNKNOWN,
                assumptions=["No backend produced a claim."],
                limits=["Absence of backend evidence cannot allow."],
                required=True,
            )
        ]

    material_payloads = [item.model_dump(mode="json") for item in obligation.materials]
    material_set_digest = material_set_digest_for_obligation(obligation)

    artifacts: list[dict[str, Any]] = []
    for result in record.results:
        artifacts.extend(result.generated_artifacts)
    for item in record.open_obligations:
        artifacts.append(dict(item))

    artifacts.append(
        {
            "kind": "routing_enforced",
            "value": routing_enforced,
            "routing_id": routing.routing_id,
            "obligation_id": obligation.obligation_id,
        }
    )

    control_plane_trace = {
        "kind": "control_plane_trace",
        "schema_version": "ovk.control_plane_trace.v2",
        "router_version": ROUTER_VERSION,
        "compiler": {
            "compiler_id": obligation.compiler_id,
            "compiler_version": obligation.compiler_version,
        },
        "coverage": obligation.coverage.model_dump(mode="json"),
        "material_set_digest": material_set_digest,
        "policy_digest": obligation.policy_digest,
        "routing_id": routing.routing_id,
        "requested_backends": list(routing.requested),
        "eligible_backends": [item.backend for item in routing.eligible],
        "selected_backends": [
            {
                "backend": item.backend,
                "required": item.required,
                "expected_guarantee": item.expected_guarantee,
            }
            for item in routing.selected
        ],
        "attempted_backends": [item.backend for item in record.attempts],
        "executed_backends": [item.backend for item in record.results],
        "execution_attempts": [item.model_dump(mode="json") for item in record.attempts],
        "routing_enforced": routing_enforced,
        "aggregation_policy": routing.aggregation_policy,
        # Full typed objects are the normative external recomputation substrate.
        "obligation": obligation.model_dump(mode="json"),
        "routing": routing.model_dump(mode="json"),
        "backend_obligations": [item.model_dump(mode="json") for item in record.backend_obligations],
        "results": [item.model_dump(mode="json") for item in record.results],
        "aggregate_status": record.aggregate_status.value,
        "decision_state": record.decision_state.value if record.decision_state is not None else None,
        "original_decision_state": (
            record.original_decision_state.value if record.original_decision_state is not None else None
        ),
        "merge_recommendation": record.merge_recommendation.value,
        "aggregation_reason": record.aggregation_reason,
        "fallback_used": record.fallback_used,
        "fallback_accepted": record.fallback_accepted,
        "fallback_cause": record.fallback_cause,
        "controlling_finding_ids": list(record.controlling_finding_ids),
    }
    artifacts.append(control_plane_trace)

    if obligation.compiler_id:
        artifacts.append(
            {
                "kind": "compiler_identity",
                "compiler_id": obligation.compiler_id,
                "compiler_version": obligation.compiler_version,
                "coverage": obligation.coverage.model_dump(mode="json"),
                "materials": material_payloads,
                "material_set_digest": material_set_digest,
            }
        )

    from ovk.core.decision import merge_recommendation_to_decision_state

    recommendation = record.merge_recommendation
    decision_state = getattr(record, "decision_state", None)
    if decision_state is None:
        decision_state = merge_recommendation_to_decision_state(recommendation)
    original_decision_state = getattr(record, "original_decision_state", None) or decision_state
    controlling_finding_ids = list(getattr(record, "controlling_finding_ids", ()) or ())
    aggregation_reason = record.aggregation_reason

    policy = coverage_policy or CoveragePolicy()
    # Strict authorization is derived from measured coverage only. A compiler
    # abstraction field is not permitted to self-assert strict-allow eligibility.
    allow_ok = strict_allow_permitted(obligation.coverage, policy)

    if (
        recommendation == MergeRecommendation.ALLOW or decision_state == DecisionState.ALLOW
    ) and not allow_ok:
        recommendation = MergeRecommendation.REQUIRE_HUMAN_REVIEW
        decision_state = DecisionState.NEEDS_REVIEW
        original_decision_state = DecisionState.NEEDS_REVIEW
        aggregation_reason = f"{aggregation_reason}; incomplete abstraction cannot allow under strict coverage"
        artifacts.append(
            {
                "kind": "incomplete_abstraction",
                "coverage": obligation.coverage.model_dump(mode="json"),
                "reason": "strict allow blocked unless measured coverage is complete or explicit coverage policy accepts partial",
            }
        )

    if recommendation == MergeRecommendation.ALLOW:
        decision_state = DecisionState.ALLOW
    elif decision_state == DecisionState.ALLOW and recommendation != MergeRecommendation.ALLOW:
        decision_state = merge_recommendation_to_decision_state(recommendation)

    decision = {
        "decision_state": decision_state.value if hasattr(decision_state, "value") else str(decision_state),
        "original_decision_state": (
            original_decision_state.value if hasattr(original_decision_state, "value") else str(original_decision_state)
        ),
        "merge_recommendation": recommendation.value,
        "human_review_required": decision_state != DecisionState.ALLOW and recommendation.value != "allow",
        "controlling_finding_ids": controlling_finding_ids,
        "aggregation_reason": aggregation_reason,
        "routing_enforced": routing_enforced,
        "fallback_used": record.fallback_used,
        "fallback_accepted": record.fallback_accepted,
        "fallback_cause": record.fallback_cause,
    }

    evidence_id = content_digest(
        {
            "obligation_id": obligation.obligation_id,
            "routing_id": routing.routing_id,
            "material_set_digest": material_set_digest,
            "results": [claim.model_dump(mode="json") for claim in claims],
        }
    )[:24]

    evidence = VerificationEvidence(
        evidence_id=f"ev-{evidence_id}",
        schema_version=schema_version,
        subject={key: value for key, value in obligation.subject.model_dump(mode="json").items() if value is not None},
        change_origin={"author_type": author_type, "agent": agent, "task": task},
        intent={
            "intent_id": obligation.intent_id,
            "title": obligation.intent_id,
            "risk": {"severity": obligation.severity.value},
        },
        backend_claims=claims,
        counterexamples=counterexamples,
        generated_artifacts=artifacts,
        decision=decision,
        obligation_id=obligation.obligation_id,
        routing_id=routing.routing_id,
        material_set_digest=material_set_digest if str(schema_version).startswith("ovk.evidence.v3") else None,
        compiler={
            "compiler_id": obligation.compiler_id,
            "compiler_version": obligation.compiler_version,
        },
        materials=material_payloads,
        coverage=obligation.coverage.model_dump(mode="json"),
        requested_backends=list(routing.requested),
        eligible_backends=[item.backend for item in routing.eligible],
        selected_backends=[item.backend for item in routing.selected],
        attempted_backends=[item.backend for item in record.attempts],
        executed_backends=[item.backend for item in record.results],
        execution_attempts=[item.model_dump(mode="json") for item in record.attempts],
        aggregation_policy=routing.aggregation_policy,
        routing_enforced=routing_enforced,
        policy_digest=obligation.policy_digest,
    )
    if str(schema_version).startswith("ovk.evidence.v3"):
        from ovk.core.evidence_integrity import seal_evidence

        return seal_evidence(evidence, policy_digest=obligation.policy_digest)
    return evidence
