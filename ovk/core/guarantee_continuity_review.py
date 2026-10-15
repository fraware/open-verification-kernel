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
from ovk.core.guarantee_assurance_ledger import (
    validate_guarantee_assurance_snapshot_structure,
)
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
    snapshot_state_reverified_at_review: Literal[False] = False
    source_snapshot_structural_issues: list[str] = Field(default_factory=list)
    target_snapshot_structural_issues: list[str] = Field(default_factory=list)
    target_evidence_origin: str | None = None
    source_definition_digest: str | None = None
    target_definition_digest: str | None = None
    source_evidence_digest: str | None = None
    target_evidence_digest: str | None = None
    declared_definition_changed: bool
    declared_machine_claim_changed: bool
    changed_specification_fields: list[str] = Field(default_factory=list)
    supplied_source_statement: str
    supplied_target_statement: str
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

        source_structure = (
            ", ".join(safe(issue) for issue in self.source_snapshot_structural_issues)
            if self.source_snapshot_structural_issues else "no structural inconsistency detected"
        )
        target_structure = (
            ", ".join(safe(issue) for issue in self.target_snapshot_structural_issues)
            if self.target_snapshot_structural_issues else "no structural inconsistency detected"
        )
        changed_fields = (
            ", ".join(safe(field) for field in self.changed_specification_fields)
            if self.changed_specification_fields else "none"
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
            f"| Source snapshot recorded typed-claim status | {safe(self.source_typed_claim_status)} |\n"
            f"| Target snapshot recorded typed-claim status | {safe(self.target_typed_claim_status)} |\n"
            f"| Target evidence origin | {safe(self.target_evidence_origin)} |\n"
            "| Snapshot state independently reverified now | **NO** |\n"
            f"| Source snapshot structural issues | {source_structure} |\n"
            f"| Target snapshot structural issues | {target_structure} |\n"
            f"| Declared definition changed | {str(self.declared_definition_changed).lower()} |\n"
            f"| Declared machine claim changed | {str(self.declared_machine_claim_changed).lower()} |\n"
            f"| Changed supplied declaration fields | {changed_fields} |\n"
            f"| Historical evidence gate | {safe(self.historical_transport)} |\n"
            f"| Governing manifest authority | {self.manifest_authority} |\n"
            f"| Live expiry / revocation | {self.live_temporal_policy} |\n"
            f"| Source-semantics refinement | {self.source_semantics_refinement} |\n"
            "| Production reliance / merge authorization | **NO** |\n\n"
            f"**Supplied source statement:** {safe(self.supplied_source_statement)}\n\n"
            f"**Supplied target statement:** {safe(self.supplied_target_statement)}\n\n"
            f"**Gate reason codes:** {reasons}.\n\n"
            f"**Next action:** {safe(self.next_action)}.\n\n"
            "The recorded snapshot status was not recomputed at review time; "
            "typed-claim establishment refers only to OVK's extracted machine "
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
    source_snapshot_issues = validate_guarantee_assurance_snapshot_structure(source)
    target_snapshot_issues = validate_guarantee_assurance_snapshot_structure(target)
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

    source_fields = source_spec.model_dump(mode="json")
    target_fields = target_spec.model_dump(mode="json")
    changed_fields = sorted(
        field for field in source_fields.keys() | target_fields.keys()
        if source_fields.get(field) != target_fields.get(field)
    )
    return GuaranteeContinuityReview(
        guarantee_id=guarantee_id,
        subject_repo=target.subject_repo,
        source_head_sha=source.subject_head_sha,
        target_head_sha=target.subject_head_sha,
        source_typed_claim_status=(
            "untrusted_snapshot" if source_snapshot_issues
            else _status(source, guarantee_id)
        ),
        target_typed_claim_status=(
            "untrusted_snapshot" if target_snapshot_issues
            else _status(target, guarantee_id)
        ),
        source_snapshot_structural_issues=source_snapshot_issues,
        target_snapshot_structural_issues=target_snapshot_issues,
        target_evidence_origin=target_origin,
        source_definition_digest=transport.source_definition_digest,
        target_definition_digest=transport.target_definition_digest,
        source_evidence_digest=transport.source_evidence_digest,
        target_evidence_digest=transport.target_evidence_digest,
        declared_definition_changed=(
            source_spec.definition_digest != target_spec.definition_digest
        ),
        changed_specification_fields=changed_fields,
        supplied_source_statement=source_spec.statement,
        supplied_target_statement=target_spec.statement,
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
