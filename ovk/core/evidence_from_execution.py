"""Convert control-plane execution records into VerificationEvidence."""

from __future__ import annotations


from typing import Any


from ovk.compilers.authorization import CoveragePolicy, strict_allow_permitted

from ovk.core.bundle import content_digest

from ovk.core.execution_models import ObligationExecutionRecord

from ovk.core.materials import material_set_digest_for_obligation

from ovk.core.models import BackendClaim, MergeRecommendation, VerificationEvidence, VerificationStatus


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
    """Project an obligation execution record into public evidence."""

    obligation = record.obligation

    routing = record.routing

    counterexamples: list[dict[str, Any]] = []

    for result in record.results:
        counterexamples.extend(result.counterexamples)

    claims = [
        BackendClaim(
            backend=result.backend,
            guarantee_type=result.guarantee_type,
            status=result.status,
            assumptions=list(result.assumptions),
            limits=list(result.limits),
            adapter_version=next(
                (item.adapter_version for item in record.backend_obligations if item.backend == result.backend),
                None,
            ),
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

    artifacts.append(
        {
            "kind": "control_plane_trace",
            "compiler": {
                "compiler_id": obligation.compiler_id,
                "compiler_version": obligation.compiler_version,
            },
            "coverage": obligation.coverage.model_dump(mode="json"),
            "material_set_digest": material_set_digest,
            "routing_id": routing.routing_id,
            "requested_backends": list(routing.requested),
            "eligible_backends": [item.backend for item in routing.eligible],
            "selected_backends": [item.backend for item in routing.selected],
            "attempted_backends": [item.backend for item in record.attempts],
            "executed_backends": [item.backend for item in record.results],
            "execution_attempts": [item.model_dump(mode="json") for item in record.attempts],
            "routing_enforced": routing_enforced,
            "aggregation_policy": routing.aggregation_policy,
        }
    )

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

    recommendation = record.merge_recommendation

    aggregation_reason = record.aggregation_reason

    policy = coverage_policy or CoveragePolicy()

    allow_ok = obligation.abstraction.get("strict_allow_permitted")

    if allow_ok is None:
        allow_ok = strict_allow_permitted(obligation.coverage, policy)

    if recommendation == MergeRecommendation.ALLOW and not allow_ok:
        recommendation = MergeRecommendation.REQUIRE_HUMAN_REVIEW

        aggregation_reason = f"{aggregation_reason}; incomplete abstraction cannot allow under strict coverage"

        artifacts.append(
            {
                "kind": "incomplete_abstraction",
                "coverage": obligation.coverage.model_dump(mode="json"),
                "reason": "strict allow blocked unless coverage complete or policy accepts partial",
            }
        )

    decision = {
        "merge_recommendation": recommendation.value,
        "human_review_required": recommendation.value != "allow",
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

    return VerificationEvidence(
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
        material_set_digest=material_set_digest if schema_version.endswith(".v3") else None,
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
    )
