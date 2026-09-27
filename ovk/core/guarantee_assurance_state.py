"""Current assurance state for durable guarantees.

This module composes the durable Guarantee Graph with sealed Protected Effect
VerificationEvidence. It intentionally does not make merge decisions.

A guarantee is ESTABLISHED only when:
1. the explicit GuaranteeSpec binds uniquely to a current ProtectedEffect;
2. exactly one current-head evidence record validates against that binding;
3. the evidence is integrity-valid, policy-bound, and (by default) signed;
4. the typed Protected Effect claim is PASS; and
5. every declared guarantee dependency is itself ESTABLISHED.

An unchanged semantic slice is not evidence and cannot establish a guarantee.
The human-readable GuaranteeSpec.statement is descriptive metadata. The machine
claim is the typed pair (guarantee_type, selector).
"""

from __future__ import annotations

import hmac
from typing import Any, Literal

from pydantic import BaseModel, Field

from ovk.core.assurance_ir import AssuranceIR
from ovk.core.evidence_integrity import (
    integrity_envelope_complete,
    is_supported_schema_version,
    recompute_input_digest,
    verify_evidence_digest,
    verify_evidence_signature,
)
from ovk.core.guarantee_graph import (
    GuaranteeBinding,
    GuaranteeGraphRevision,
    GuaranteeSpec,
    build_guarantee_graph_revision,
)
from ovk.core.models import VerificationEvidence, VerificationStatus
from ovk.core.protected_effect_evaluation import ProtectedEffectIntegrityEvaluation
from ovk.core.protected_effect_evidence import (
    PROTECTED_EFFECT_CHECKER_ID,
    PROTECTED_EFFECT_CHECKER_VERSION,
    PROTECTED_EFFECT_GUARANTEE,
)


GuaranteeAssuranceStatus = Literal[
    "established",
    "violated",
    "unknown",
    "unbound",
    "invalid_evidence",
    "dependency_unestablished",
]
GuaranteeEvidenceOrigin = Literal["fresh", "reused"]


class GuaranteeAssurancePolicy(BaseModel):
    """Policy controlling admission of evidence into durable assurance state."""

    require_signature: bool = True
    require_complete_coverage_for_pass: bool = True


class GuaranteeAssuranceState(BaseModel):
    """Current assurance state of one durable guarantee."""

    guarantee_id: str
    guarantee_definition_digest: str
    machine_claim: dict[str, Any]
    display_statement: str
    binding: GuaranteeBinding

    local_status: GuaranteeAssuranceStatus
    status: GuaranteeAssuranceStatus
    reason_codes: list[str] = Field(default_factory=list)

    evidence_id: str | None = None
    evidence_digest: str | None = None
    evidence_origin: GuaranteeEvidenceOrigin | None = None
    protected_effect_claim_status: str | None = None

    dependencies: list[str] = Field(default_factory=list)
    dependency_statuses: dict[str, GuaranteeAssuranceStatus] = Field(
        default_factory=dict
    )


class GuaranteeAssuranceSnapshot(BaseModel):
    """Durable guarantee state materialized for one exact repository revision."""

    assurance_ir_digest: str
    subject_repo: str
    subject_head_sha: str
    policy_digest: str
    graph: GuaranteeGraphRevision
    states: list[GuaranteeAssuranceState]

    def state_for(self, guarantee_id: str) -> GuaranteeAssuranceState:
        matches = [item for item in self.states if item.guarantee_id == guarantee_id]
        if len(matches) != 1:
            raise ValueError(f"guarantee state missing or duplicated: {guarantee_id}")
        return matches[0]


class _EvidenceAdmission(BaseModel):
    status: GuaranteeAssuranceStatus
    reason_codes: list[str] = Field(default_factory=list)
    evidence_id: str | None = None
    evidence_digest: str | None = None
    evidence_origin: GuaranteeEvidenceOrigin | None = None
    claim_status: str | None = None


def _single_artifact(
    evidence: VerificationEvidence,
    kind: str,
) -> dict[str, Any] | None:
    matches = [
        item
        for item in evidence.generated_artifacts
        if item.get("kind") == kind
    ]
    return matches[0] if len(matches) == 1 else None


def _candidate_evidence_for_effect(
    evidence_items: list[VerificationEvidence],
    protected_effect_id: str,
) -> list[VerificationEvidence]:
    return [
        evidence
        for evidence in evidence_items
        if str(evidence.intent.get("protected_effect_id") or "")
        == protected_effect_id
    ]


def _admit_evidence(
    evidence: VerificationEvidence,
    *,
    ir: AssuranceIR,
    binding: GuaranteeBinding,
    expected_policy_digest: str,
    policy: GuaranteeAssurancePolicy,
    signature_key: bytes | None,
) -> _EvidenceAdmission:
    """Validate one evidence record against one exact current guarantee binding."""

    reasons: list[str] = []

    if binding.status != "bound" or binding.protected_effect_id is None:
        return _EvidenceAdmission(
            status="invalid_evidence",
            reason_codes=["guarantee_binding_not_bound"],
        )

    if not is_supported_schema_version(evidence.schema_version):
        reasons.append("unsupported_schema")
    if not integrity_envelope_complete(evidence):
        reasons.append("incomplete_integrity_envelope")
    if not verify_evidence_digest(evidence):
        reasons.append("invalid_evidence_digest")

    if evidence.input_digest is None:
        reasons.append("missing_input_digest")
    else:
        expected_input_digest = recompute_input_digest(evidence)
        if not hmac.compare_digest(evidence.input_digest, expected_input_digest):
            reasons.append("input_digest_mismatch")

    if evidence.signature is None:
        if policy.require_signature:
            reasons.append("signature_required")
    elif not verify_evidence_signature(evidence, key=signature_key):
        reasons.append("invalid_signature")

    if evidence.policy_digest != expected_policy_digest:
        reasons.append("policy_digest_mismatch")
    if evidence.checker_id != PROTECTED_EFFECT_CHECKER_ID:
        reasons.append("checker_id_mismatch")
    if evidence.checker_version != PROTECTED_EFFECT_CHECKER_VERSION:
        reasons.append("checker_version_mismatch")

    if str(evidence.subject.get("repo") or "") != ir.subject.repo:
        reasons.append("repository_mismatch")
    if str(evidence.subject.get("head_sha") or "") != ir.subject.head_sha:
        reasons.append("head_revision_mismatch")

    if evidence.intent.get("protected_effect_id") != binding.protected_effect_id:
        reasons.append("protected_effect_mismatch")
    if (
        evidence.intent.get("semantic_slice_digest")
        != binding.semantic_slice_digest
    ):
        reasons.append("semantic_slice_mismatch")

    semantic_artifact = _single_artifact(
        evidence, "protected_effect_semantic_slice"
    )
    if semantic_artifact is None:
        reasons.append("missing_or_ambiguous_semantic_slice_artifact")
    else:
        if (
            semantic_artifact.get("protected_effect_id")
            != binding.protected_effect_id
        ):
            reasons.append("semantic_artifact_effect_mismatch")
        if (
            semantic_artifact.get("semantic_slice_digest")
            != binding.semantic_slice_digest
        ):
            reasons.append("semantic_artifact_digest_mismatch")

    change_source = str(evidence.change_origin.get("source") or "")

    evaluation_artifact = _single_artifact(
        evidence, "protected_effect_integrity_evaluation"
    )
    evaluation: ProtectedEffectIntegrityEvaluation | None = None
    if evaluation_artifact is not None:
        try:
            evaluation = ProtectedEffectIntegrityEvaluation.model_validate(
                evaluation_artifact.get("evaluation")
            )
        except Exception:
            reasons.append("invalid_evaluation_artifact")
    elif change_source == "assurance_ir":
        reasons.append("missing_or_ambiguous_evaluation_artifact")

    if evaluation is not None:
        if evaluation.assurance_ir_digest != ir.assurance_ir_digest:
            reasons.append("evaluation_ir_digest_mismatch")
        if evaluation.protected_effect_id != binding.protected_effect_id:
            reasons.append("evaluation_effect_mismatch")

    claims = [
        claim
        for claim in evidence.backend_claims
        if claim.backend == PROTECTED_EFFECT_CHECKER_ID
        and claim.guarantee_type == PROTECTED_EFFECT_GUARANTEE
    ]
    claim = claims[0] if len(claims) == 1 else None
    if claim is None:
        reasons.append("missing_or_ambiguous_protected_effect_claim")
    else:
        if claim.required:
            reasons.append("protected_effect_claim_not_shadow")
        if evaluation is not None and claim.status.value != evaluation.status:
            reasons.append("claim_evaluation_status_mismatch")

    if str(evidence.decision.get("decision_state") or "") != "needs_review":
        reasons.append("evidence_not_shadow_decision")
    if list(evidence.decision.get("controlling_finding_ids") or []):
        reasons.append("evidence_has_controlling_findings")

    origin: GuaranteeEvidenceOrigin | None = None
    if change_source == "assurance_ir":
        origin = "fresh"
        if (
            evidence.change_origin.get("assurance_ir_digest")
            != ir.assurance_ir_digest
        ):
            reasons.append("fresh_evidence_ir_digest_mismatch")
    elif change_source == "reused_sealed_evidence":
        origin = "reused"
        if (
            evidence.change_origin.get("head_assurance_ir_digest")
            != ir.assurance_ir_digest
        ):
            reasons.append("reused_evidence_ir_digest_mismatch")
        reuse_artifact = _single_artifact(
            evidence, "protected_effect_evidence_reuse"
        )
        if reuse_artifact is None:
            reasons.append("missing_or_ambiguous_reuse_artifact")
        else:
            reuse_decision = reuse_artifact.get("reuse_decision")
            if not isinstance(reuse_decision, dict):
                reasons.append("invalid_reuse_decision")
            elif reuse_decision.get("eligible") is not True:
                reasons.append("reuse_decision_not_eligible")
            if not reuse_artifact.get("prior_evidence_digest"):
                reasons.append("missing_prior_evidence_digest")
    else:
        reasons.append("unknown_evidence_origin")

    if reasons:
        return _EvidenceAdmission(
            status="invalid_evidence",
            reason_codes=sorted(set(reasons)),
            evidence_id=evidence.evidence_id,
            evidence_digest=evidence.evidence_digest,
            evidence_origin=origin,
            claim_status=claim.status.value if claim is not None else None,
        )

    assert claim is not None
    if claim.status == VerificationStatus.PASS:
        coverage = evidence.coverage or {}
        if (
            policy.require_complete_coverage_for_pass
            and str(coverage.get("status") or "") != "complete"
        ):
            return _EvidenceAdmission(
                status="invalid_evidence",
                reason_codes=["pass_requires_complete_coverage"],
                evidence_id=evidence.evidence_id,
                evidence_digest=evidence.evidence_digest,
                evidence_origin=origin,
                claim_status=claim.status.value,
            )
        status: GuaranteeAssuranceStatus = "established"
    elif claim.status == VerificationStatus.FAIL:
        status = "violated"
    else:
        status = "unknown"

    return _EvidenceAdmission(
        status=status,
        reason_codes=[],
        evidence_id=evidence.evidence_id,
        evidence_digest=evidence.evidence_digest,
        evidence_origin=origin,
        claim_status=claim.status.value,
    )


def build_guarantee_assurance_snapshot(
    ir: AssuranceIR,
    specs: list[GuaranteeSpec],
    evidence_items: list[VerificationEvidence],
    *,
    policy_digest: str,
    assurance_policy: GuaranteeAssurancePolicy | None = None,
    signature_key: bytes | None = None,
) -> GuaranteeAssuranceSnapshot:
    """Materialize current assurance state from typed guarantees and sealed evidence.

    Evidence may be freshly produced for this head or reissued by the strict
    Protected Effect reuse path. The snapshot does not itself perform reuse.
    """

    expected_policy_digest = policy_digest.strip()
    if not expected_policy_digest:
        raise ValueError("policy_digest must be non-empty")

    policy = assurance_policy or GuaranteeAssurancePolicy()
    graph = build_guarantee_graph_revision(ir, specs)
    spec_by_id = {spec.guarantee_id: spec for spec in specs}

    local_states: dict[str, GuaranteeAssuranceState] = {}
    for binding in graph.bindings:
        spec = spec_by_id[binding.guarantee_id]
        machine_claim = {
            "guarantee_type": spec.guarantee_type,
            "selector": spec.selector.model_dump(mode="json"),
        }

        if binding.status != "bound" or binding.protected_effect_id is None:
            local_states[spec.guarantee_id] = GuaranteeAssuranceState(
                guarantee_id=spec.guarantee_id,
                guarantee_definition_digest=spec.definition_digest,
                machine_claim=machine_claim,
                display_statement=spec.statement,
                binding=binding,
                local_status="unbound",
                status="unbound",
                reason_codes=[f"binding_{binding.status}"],
                dependencies=list(spec.dependencies),
            )
            continue

        candidates = _candidate_evidence_for_effect(
            evidence_items, binding.protected_effect_id
        )
        if len(candidates) != 1:
            reasons = (
                ["missing_current_evidence"]
                if not candidates
                else ["ambiguous_current_evidence"]
            )
            local_states[spec.guarantee_id] = GuaranteeAssuranceState(
                guarantee_id=spec.guarantee_id,
                guarantee_definition_digest=spec.definition_digest,
                machine_claim=machine_claim,
                display_statement=spec.statement,
                binding=binding,
                local_status="invalid_evidence",
                status="invalid_evidence",
                reason_codes=reasons,
                dependencies=list(spec.dependencies),
            )
            continue

        admission = _admit_evidence(
            candidates[0],
            ir=ir,
            binding=binding,
            expected_policy_digest=expected_policy_digest,
            policy=policy,
            signature_key=signature_key,
        )
        local_states[spec.guarantee_id] = GuaranteeAssuranceState(
            guarantee_id=spec.guarantee_id,
            guarantee_definition_digest=spec.definition_digest,
            machine_claim=machine_claim,
            display_statement=spec.statement,
            binding=binding,
            local_status=admission.status,
            status=admission.status,
            reason_codes=admission.reason_codes,
            evidence_id=admission.evidence_id,
            evidence_digest=admission.evidence_digest,
            evidence_origin=admission.evidence_origin,
            protected_effect_claim_status=admission.claim_status,
            dependencies=list(spec.dependencies),
        )

    resolved: dict[str, GuaranteeAssuranceState] = {}

    def resolve(guarantee_id: str) -> GuaranteeAssuranceState:
        if guarantee_id in resolved:
            return resolved[guarantee_id]

        state = local_states[guarantee_id]
        dependency_states = {
            dependency: resolve(dependency).status
            for dependency in state.dependencies
        }
        final_status = state.local_status
        reasons = list(state.reason_codes)

        if state.local_status == "established":
            unestablished = sorted(
                dependency
                for dependency, status in dependency_states.items()
                if status != "established"
            )
            if unestablished:
                final_status = "dependency_unestablished"
                reasons.append(
                    "dependencies_not_established:"
                    + ",".join(unestablished)
                )

        resolved_state = state.model_copy(
            update={
                "status": final_status,
                "reason_codes": sorted(set(reasons)),
                "dependency_statuses": dependency_states,
            }
        )
        resolved[guarantee_id] = resolved_state
        return resolved_state

    states = [resolve(guarantee_id) for guarantee_id in sorted(local_states)]
    return GuaranteeAssuranceSnapshot(
        assurance_ir_digest=ir.assurance_ir_digest,
        subject_repo=ir.subject.repo,
        subject_head_sha=ir.subject.head_sha,
        policy_digest=expected_policy_digest,
        graph=graph,
        states=states,
    )
