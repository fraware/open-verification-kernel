"""Non-controlling reviewer report for predecessor-bound guarantee continuity.

This adapter consumes typed assurance snapshots and delegates historical
evidence admission to the existing guarantee transport gate. It never
converts conditional eligibility into deployment, merge, or reliance authority.
"""

from __future__ import annotations

from html import escape
from typing import Literal

from pydantic import BaseModel, Field

from ovk.core.guarantee_assurance_state import GuaranteeAssuranceSnapshot
from ovk.core.guarantee_graph import GuaranteeSpec
from ovk.core.guarantee_transport import evaluate_guarantee_transport_admission
from ovk.core.models import VerificationEvidence


class GuaranteeContinuityReview(BaseModel):
    """Advisory cross-revision record, with explicitly unresolved trust checks."""

    schema_version: Literal["ovk.guarantee_continuity_review.v1"] = (
        "ovk.guarantee_continuity_review.v1"
    )
    guarantee_id: str
    subject_repo: str
    source_head_sha: str
    target_head_sha: str
    source_typed_claim_status: str
    target_typed_claim_status: str
    target_evidence_origin: str | None = None
    source_definition_digest: str | None = None
    target_definition_digest: str | None = None
    source_evidence_digest: str | None = None
    target_evidence_digest: str | None = None
    declared_definition_changed: bool
    declared_machine_claim_changed: bool
    historical_transport: Literal["conditional_candidate", "not_admitted"]
    transport_reason_codes: list[str] = Field(default_factory=list)
    manifest_authority: Literal["not_authenticated"] = "not_authenticated"
    live_temporal_policy: Literal["not_evaluated"] = "not_evaluated"
    source_semantics_refinement: Literal["unproved"] = "unproved"
    decision_scope: Literal["advisory_only"] = "advisory_only"
    production_reliance_authorized: Literal[False] = False
    next_action: Literal[
        "authenticate_context_and_run_live_policy_checks",
        "obtain_fresh_evidence_or_independent_review",
    ]

    def to_markdown(self) -> str:
        """Escape caller-supplied text in the Markdown reviewer view."""

        def safe(value: object) -> str:
            text = escape(str(value) if value is not None else "unknown", quote=True)
            return (
                text.replace("\\", "\\\\")
                .replace("|", "\\|")
                .replace("[", "\\[")
                .replace("]", "\\]")
                .replace("\r", " ")
                .replace("\n", " ")
            )

        reasons = (
            ", ".join(safe(reason) for reason in self.transport_reason_codes)
            if self.transport_reason_codes else "none under this bounded gate"
        )
        return (
            "# Guarantee continuity review — advisory only\n\n"
            f"**Guarantee:** {safe(self.guarantee_id)}\n\n"
            f"**Repository:** {safe(self.subject_repo)}\n\n"
            f"**Source to target:** {safe(self.source_head_sha)} to "
            f"{safe(self.target_head_sha)}\n\n"
            "| Review dimension | Result |\n"
            "| --- | --- |\n"
            f"| Source typed claim | {safe(self.source_typed_claim_status)} |\n"
            f"| Target typed claim | {safe(self.target_typed_claim_status)} |\n"
            f"| Target evidence origin | {safe(self.target_evidence_origin)} |\n"
            f"| Declared definition changed | {str(self.declared_definition_changed).lower()} |\n"
            f"| Declared machine claim changed | {str(self.declared_machine_claim_changed).lower()} |\n"
            f"| Historical evidence gate | {safe(self.historical_transport)} |\n"
            f"| Governing manifest authority | {self.manifest_authority} |\n"
            f"| Live expiry / revocation | {self.live_temporal_policy} |\n"
            f"| Source-semantics refinement | {self.source_semantics_refinement} |\n"
            "| Production reliance / merge authorization | **NO** |\n\n"
            f"**Gate reason codes:** {reasons}.\n\n"
            f"**Next action:** {safe(self.next_action)}.\n\n"
            "Target typed-claim status refers only to OVK's extracted machine "
            "claim. Conditional historical eligibility compares supplied "
            "declarations and signed evidence. It does not authenticate "
            "governing Git manifests, re-check temporal expiry/revocation, "
            "prove source-code semantics, or authorize deployment. "
            "Ineligibility does not prove the target claim false.\n"
        )


def _status(snapshot: GuaranteeAssuranceSnapshot, guarantee_id: str) -> str:
    """Return unknown for an absent or ambiguous snapshot state."""
    try:
        return snapshot.state_for(guarantee_id).status
    except ValueError:
        return "unknown"


def build_guarantee_continuity_review(
    source: GuaranteeAssuranceSnapshot,
    target: GuaranteeAssuranceSnapshot,
    *,
    guarantee_id: str,
    source_spec: GuaranteeSpec,
    target_spec: GuaranteeSpec,
    source_evidence: VerificationEvidence,
    target_evidence: VerificationEvidence,
    signature_key: bytes | None,
) -> GuaranteeContinuityReview:
    """Report current claim and predecessor transport as distinct assertions.

    Source and target declarations are caller-selected and their Git authority
    is unverified here. Live expiration, revocation and source semantics are
    also outside this function, so no result authorizes production reliance.
    """
    transport = evaluate_guarantee_transport_admission(
        source,
        target,
        guarantee_id=guarantee_id,
        source_spec=source_spec,
        target_spec=target_spec,
        source_evidence=source_evidence,
        target_evidence=target_evidence,
        signature_key=signature_key,
    )
    try:
        target_origin = target.state_for(guarantee_id).evidence_origin
    except ValueError:
        target_origin = None

    return GuaranteeContinuityReview(
        guarantee_id=guarantee_id,
        subject_repo=target.subject_repo,
        source_head_sha=source.subject_head_sha,
        target_head_sha=target.subject_head_sha,
        source_typed_claim_status=_status(source, guarantee_id),
        target_typed_claim_status=_status(target, guarantee_id),
        target_evidence_origin=target_origin,
        source_definition_digest=transport.source_definition_digest,
        target_definition_digest=transport.target_definition_digest,
        source_evidence_digest=transport.source_evidence_digest,
        target_evidence_digest=transport.target_evidence_digest,
        declared_definition_changed=(
            source_spec.definition_digest != target_spec.definition_digest
        ),
        declared_machine_claim_changed=(
            source_spec.guarantee_type != target_spec.guarantee_type
            or source_spec.selector != target_spec.selector
        ),
        historical_transport=(
            "conditional_candidate" if transport.eligible else "not_admitted"
        ),
        transport_reason_codes=transport.reason_codes,
        next_action=(
            "authenticate_context_and_run_live_policy_checks"
            if transport.eligible else "obtain_fresh_evidence_or_independent_review"
        ),
    )
