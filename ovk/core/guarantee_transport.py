"""Conservative guarantee-level transport admission for consecutive revisions.

This module is a *claim-continuity gate* above Protected Effect evidence reuse.
It does not execute a checker, determine target truth, or change deployment
authority. In particular, an eligible decision is relative to OVK's declared
extractor and Protected Effect semantics, not an external soundness theorem.

The ordinary GuaranteeAssuranceSnapshot describes the current typed machine
claim. A guarantee-level transport decision additionally needs the predecessor
guarantee definition and the actual signed evidence-reuse lineage.
"""

from __future__ import annotations

import hmac

from pydantic import BaseModel, Field

from ovk.core.evidence_integrity import (
    recompute_input_digest,
    verify_evidence_digest,
    verify_evidence_signature,
)
from ovk.core.guarantee_assurance_ledger import (
    validate_guarantee_assurance_snapshot_structure,
)
from ovk.core.guarantee_assurance_state import GuaranteeAssuranceSnapshot
from ovk.core.guarantee_graph import GuaranteeSpec
from ovk.core.models import VerificationEvidence, VerificationStatus
from ovk.core.protected_effect_evidence import (
    PROTECTED_EFFECT_CHECKER_ID,
    PROTECTED_EFFECT_CHECKER_VERSION,
    PROTECTED_EFFECT_GUARANTEE,
)


class GuaranteeTransportAdmission(BaseModel):
    """Recorded *conditional* eligibility for same-claim evidence transport.

    `eligible=True` states only that the specified snapshots and evidence
    objects satisfy these concrete identity, integrity, and lineage checks.
    It does not claim independent verification of extracted program semantics.
    """

    guarantee_id: str
    eligible: bool
    reason_codes: list[str] = Field(default_factory=list)
    source_definition_digest: str | None = None
    target_definition_digest: str | None = None
    source_evidence_digest: str | None = None
    target_evidence_digest: str | None = None


def _reuse_artifact(evidence: VerificationEvidence) -> dict | None:
    artifacts = [
        item
        for item in evidence.generated_artifacts
        if isinstance(item, dict)
        and item.get("kind") == "protected_effect_evidence_reuse"
    ]
    return artifacts[0] if len(artifacts) == 1 else None


def _signed_integrity_reasons(
    evidence: VerificationEvidence,
    *,
    key: bytes | None,
    role: str,
) -> list[str]:
    reasons: list[str] = []
    if not verify_evidence_digest(evidence):
        reasons.append(f"{role}_evidence_digest_invalid")
    if evidence.input_digest is None or not hmac.compare_digest(
        evidence.input_digest, recompute_input_digest(evidence)
    ):
        reasons.append(f"{role}_input_digest_invalid")
    if evidence.signature is None:
        reasons.append(f"{role}_signature_missing")
    elif key is None or not verify_evidence_signature(evidence, key=key):
        reasons.append(f"{role}_signature_invalid_or_key_missing")
    claims = [
        claim
        for claim in evidence.backend_claims
        if claim.backend == PROTECTED_EFFECT_CHECKER_ID
        and claim.guarantee_type == PROTECTED_EFFECT_GUARANTEE
    ]
    if len(claims) != 1 or claims[0].status != VerificationStatus.PASS:
        reasons.append(f"{role}_pe_pass_claim_missing_or_ambiguous")
    elif claims[0].required:
        reasons.append(f"{role}_pe_claim_not_shadow")
    if evidence.checker_id != PROTECTED_EFFECT_CHECKER_ID:
        reasons.append(f"{role}_checker_id_mismatch")
    if evidence.checker_version != PROTECTED_EFFECT_CHECKER_VERSION:
        reasons.append(f"{role}_checker_version_mismatch")
    return reasons


def evaluate_guarantee_transport_admission(
    source: GuaranteeAssuranceSnapshot,
    target: GuaranteeAssuranceSnapshot,
    *,
    guarantee_id: str,
    source_spec: GuaranteeSpec,
    target_spec: GuaranteeSpec,
    source_evidence: VerificationEvidence,
    target_evidence: VerificationEvidence,
    signature_key: bytes | None,
) -> GuaranteeTransportAdmission:
    """Conservatively admit immediate-predecessor guarantee evidence transport.

    The caller must provide the *exact* source and target evidence records.
    Reuse chains skipping the supplied source snapshot are deliberately rejected;
    a longer-chain admission needs its own explicit, audited ancestry proof.

    The caller supplies separately selected source/target declarations; their
    authority as the governing manifests is an explicit external assumption.
    We recompute their content digests and compare each against its snapshot.
    This cannot authenticate a snapshot's originating repository revision.

    All rejection reasons are structural or cryptographic. Missing information
    does not license positive reuse. A rejection is not a proof of a violated
    target claim. The output is non-controlling and never authorizes deployment.
    """

    reasons: list[str] = []
    for role, snapshot in (("source", source), ("target", target)):
        if validate_guarantee_assurance_snapshot_structure(snapshot):
            reasons.append(f"{role}_snapshot_invalid")

    if source.subject_repo != target.subject_repo:
        reasons.append("repository_changed")
    if target.subject_base_sha != source.subject_head_sha:
        reasons.append("revision_chain_discontinuous")
    if source.policy_digest != target.policy_digest:
        reasons.append("policy_changed")

    source_digest = source.graph.spec_definition_digests.get(guarantee_id)
    target_digest = target.graph.spec_definition_digests.get(guarantee_id)
    if not source_digest or not target_digest:
        reasons.append("guarantee_missing")
    elif source_digest != target_digest:
        # The full GuaranteeSpec digest includes assumptions, selector,
        # dependencies and descriptive metadata. Conservative by design.
        reasons.append("guarantee_definition_changed")

    for role, snapshot, spec, recorded_digest in (
        ("source", source, source_spec, source_digest),
        ("target", target, target_spec, target_digest),
    ):
        if spec.guarantee_id != guarantee_id:
            reasons.append(f"{role}_declaration_identity_mismatch")
        if spec.definition_digest != recorded_digest:
            reasons.append(f"{role}_declaration_digest_mismatch")
        if sorted(snapshot.graph.dependency_edges.get(guarantee_id, [])) != sorted(
            spec.dependencies
        ):
            reasons.append(f"{role}_declaration_dependency_mismatch")

    source_state = None
    target_state = None
    try:
        source_state = source.state_for(guarantee_id)
        target_state = target.state_for(guarantee_id)
    except ValueError:
        reasons.append("guarantee_state_missing_or_ambiguous")

    for role, spec, state in (
        ("source", source_spec, source_state),
        ("target", target_spec, target_state),
    ):
        if state is None:
            continue
        expected_machine_claim = {
            "guarantee_type": spec.guarantee_type,
            "selector": spec.selector.model_dump(mode="json"),
        }
        if state.machine_claim != expected_machine_claim:
            reasons.append(f"{role}_snapshot_machine_claim_mismatch")
        if state.display_statement != spec.statement:
            reasons.append(f"{role}_snapshot_statement_mismatch")
        if sorted(state.dependencies) != sorted(spec.dependencies):
            reasons.append(f"{role}_snapshot_dependencies_mismatch")

    if source_state is not None and target_state is not None:
        if source_state.machine_claim != target_state.machine_claim:
            reasons.append("typed_machine_claim_changed")
        if source_state.protected_effect_claim_status != "pass":
            reasons.append("source_claim_status_not_pass")
        if target_state.protected_effect_claim_status != "pass":
            reasons.append("target_claim_status_not_pass")
        if source_state.status != "established":
            reasons.append("source_guarantee_not_established")
        if target_state.status != "established":
            reasons.append("target_guarantee_not_established")
        if target_state.evidence_origin != "reused":
            reasons.append("target_evidence_not_reused")
        if source_state.binding.status != "bound" or target_state.binding.status != "bound":
            reasons.append("binding_unresolved")
        if source_state.binding.protected_effect_id != target_state.binding.protected_effect_id:
            reasons.append("protected_effect_identity_changed")
        if source_state.binding.semantic_slice_digest != target_state.binding.semantic_slice_digest:
            reasons.append("semantic_support_changed")
        if source_state.evidence_digest != source_evidence.evidence_digest:
            reasons.append("source_state_evidence_mismatch")
        if target_state.evidence_digest != target_evidence.evidence_digest:
            reasons.append("target_state_evidence_mismatch")

        effect_id = target_state.binding.protected_effect_id
        semantic_digest = target_state.binding.semantic_slice_digest
        for role, ev in (("source", source_evidence), ("target", target_evidence)):
            if ev.intent.get("protected_effect_id") != effect_id:
                reasons.append(f"{role}_evidence_effect_mismatch")
            if ev.intent.get("semantic_slice_digest") != semantic_digest:
                reasons.append(f"{role}_evidence_semantic_mismatch")

    for role, snapshot, evidence in (
        ("source", source, source_evidence),
        ("target", target, target_evidence),
    ):
        if str(evidence.subject.get("repo") or "") != snapshot.subject_repo:
            reasons.append(f"{role}_evidence_repo_mismatch")
        if str(evidence.subject.get("head_sha") or "") != snapshot.subject_head_sha:
            reasons.append(f"{role}_evidence_revision_mismatch")
        if evidence.policy_digest != snapshot.policy_digest:
            reasons.append(f"{role}_evidence_policy_mismatch")
        coverage = evidence.coverage
        if not isinstance(coverage, dict) or coverage.get("status") != "complete":
            reasons.append(f"{role}_coverage_not_complete")
        if evidence.decision.get("decision_state") != "needs_review":
            reasons.append(f"{role}_evidence_not_shadow")
        if evidence.decision.get("controlling_finding_ids"):
            reasons.append(f"{role}_controlling_findings_present")
        reasons.extend(_signed_integrity_reasons(evidence, key=signature_key, role=role))

    if target_evidence.change_origin.get("source") != "reused_sealed_evidence":
        reasons.append("target_origin_not_reused")
    if target_evidence.change_origin.get("prior_evidence_digest") != source_evidence.evidence_digest:
        reasons.append("prior_evidence_lineage_mismatch")

    reuse = _reuse_artifact(target_evidence)
    if reuse is None:
        reasons.append("reuse_artifact_missing_or_ambiguous")
    else:
        if reuse.get("prior_evidence_digest") != source_evidence.evidence_digest:
            reasons.append("reuse_artifact_prior_mismatch")
        decision = reuse.get("reuse_decision")
        if not isinstance(decision, dict) or decision.get("eligible") is not True:
            reasons.append("reuse_decision_missing_or_ineligible")
        else:
            if decision.get("evidence_digest") != source_evidence.evidence_digest:
                reasons.append("reuse_decision_source_mismatch")
            if target_state is not None:
                if decision.get("protected_effect_id") != target_state.binding.protected_effect_id:
                    reasons.append("reuse_decision_effect_mismatch")
                if decision.get("semantic_slice_digest") != target_state.binding.semantic_slice_digest:
                    reasons.append("reuse_decision_semantic_mismatch")

    reason_codes = sorted(set(reasons))
    return GuaranteeTransportAdmission(
        guarantee_id=guarantee_id,
        eligible=not reason_codes,
        reason_codes=reason_codes,
        source_definition_digest=source_digest,
        target_definition_digest=target_digest,
        source_evidence_digest=source_evidence.evidence_digest,
        target_evidence_digest=target_evidence.evidence_digest,
    )
