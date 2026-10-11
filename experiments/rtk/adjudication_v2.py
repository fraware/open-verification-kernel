"""Prospective v2 *label normalization* for externally adjudicated RTK cases.

This module does NOT execute an oracle, prove checker independence, or verify
the bytes addressed by artifact digests. Callers must independently authenticate
the native checker, source evidence, target claim/context and witness contents.
It is development-only and does not retroactively alter frozen selection v1.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


HexDigest = str
ClaimStatus = Literal["ESTABLISHED", "REFUTED", "UNKNOWN"]
Applicability = Literal["ADMISSIBLE", "INADMISSIBLE", "UNDETERMINED"]
TransportVerdict = Literal[
    "VALID", "INVALID", "REVALIDATION_REQUIRED", "UNRESOLVED"
]
WitnessKind = Literal[
    "EXACT_CERTIFICATE_REPLAY",
    "INDEPENDENT_SEMANTIC_CONTINUITY",
    "EXPLICIT_INAPPLICABILITY",
    "TARGET_NATIVE_ESTABLISHMENT",
    "SAME_SUBJECT_REFUTATION",
]

_SHA256 = r"^[a-f0-9]{64}$"
_ADMISSIBLE_WITNESSES = frozenset({
    "EXACT_CERTIFICATE_REPLAY", "INDEPENDENT_SEMANTIC_CONTINUITY"
})


class ExternalWitnessRecord(BaseModel):
    """Unverified references to *external*, independently produced evidence.

    The record contains no SUT prediction or reuse decision, and cannot by
    itself prove that a claimed native verification occurred.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: WitnessKind
    verifier_identity: str = Field(min_length=1)
    checker_invocation_sha256: HexDigest = Field(pattern=_SHA256)
    artifact_sha256: HexDigest = Field(pattern=_SHA256)
    target_claim_sha256: HexDigest = Field(pattern=_SHA256)
    target_context_sha256: HexDigest = Field(pattern=_SHA256)
    source_evidence_sha256: HexDigest | None = Field(
        default=None, pattern=_SHA256
    )


class TransportAdjudicationInput(BaseModel):
    """Separate independent target-truth and old-evidence-applicability axes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["rtk.adjudication.v2-development"]
    case_id: str = Field(min_length=1)
    source_evidence_sha256: HexDigest = Field(pattern=_SHA256)
    target_claim_sha256: HexDigest = Field(pattern=_SHA256)
    target_context_sha256: HexDigest = Field(pattern=_SHA256)

    target_claim_status: ClaimStatus
    historical_evidence_applicability: Applicability

    applicability_witness: ExternalWitnessRecord | None = None
    target_establishment_witness: ExternalWitnessRecord | None = None
    target_refutation_witness: ExternalWitnessRecord | None = None
    operational_failure: str | None = None

    @model_validator(mode="after")
    def validate_adjudication_basis(self) -> "TransportAdjudicationInput":
        if self.operational_failure is not None:
            if not self.operational_failure.strip():
                raise ValueError("empty operational failure")
            if (
                self.target_claim_status != "UNKNOWN"
                or self.historical_evidence_applicability != "UNDETERMINED"
                or self.applicability_witness is not None
                or self.target_establishment_witness is not None
                or self.target_refutation_witness is not None
            ):
                raise ValueError("operational failure cannot assert resolved axes")
            return self

        def check_context(witness: ExternalWitnessRecord) -> None:
            if (
                witness.target_claim_sha256 != self.target_claim_sha256
                or witness.target_context_sha256 != self.target_context_sha256
            ):
                raise ValueError("witness target claim/context does not match case")

        for witness in (
            self.applicability_witness,
            self.target_establishment_witness,
            self.target_refutation_witness,
        ):
            if witness is not None:
                check_context(witness)

        app = self.historical_evidence_applicability
        witness = self.applicability_witness
        if app == "UNDETERMINED":
            if witness is not None:
                raise ValueError("undetermined applicability cannot carry a decisive witness")
        else:
            if witness is None:
                raise ValueError("resolved applicability requires external witness")
            if witness.source_evidence_sha256 != self.source_evidence_sha256:
                raise ValueError("applicability witness must bind exact old evidence")
            if app == "ADMISSIBLE" and witness.kind not in _ADMISSIBLE_WITNESSES:
                raise ValueError("admissibility requires replay or independent continuity")
            if app == "INADMISSIBLE" and witness.kind != "EXPLICIT_INAPPLICABILITY":
                raise ValueError("inapplicability requires a direct independent witness")

        truth = self.target_claim_status
        if truth == "ESTABLISHED":
            witness = self.target_establishment_witness
            if witness is None or witness.kind != "TARGET_NATIVE_ESTABLISHMENT":
                raise ValueError("established truth needs target-native acceptance witness")
        elif self.target_establishment_witness is not None:
            raise ValueError("unexpected target establishment witness")

        if truth == "REFUTED":
            witness = self.target_refutation_witness
            if witness is None or witness.kind != "SAME_SUBJECT_REFUTATION":
                raise ValueError("refuted truth needs authoritative same-subject witness")
        elif self.target_refutation_witness is not None:
            raise ValueError("unexpected target refutation witness")

        return self


class TransportAdjudicationVerdict(BaseModel):
    """Pure derived classification, with explicit unresolved/conflict cases."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    verdict: TransportVerdict
    reason_code: str
    adjudicated_historical_applicability: bool
    adjudicated_target_truth: bool


def derive_transport_verdict(
    record: TransportAdjudicationInput,
) -> TransportAdjudicationVerdict:
    """Apply a fixed truth table; never import SUT outputs or infer applicability."""

    # Always revalidate externally supplied records at the normalization boundary,
    # including objects constructed with unchecked model_copy(update=...).
    checked = TransportAdjudicationInput.model_validate(
        record.model_dump(mode="json")
    )
    app = checked.historical_evidence_applicability
    truth = checked.target_claim_status
    if checked.operational_failure is not None:
        verdict, reason = "UNRESOLVED", "operational_failure"
    elif app == "ADMISSIBLE" and truth == "REFUTED":
        verdict, reason = "UNRESOLVED", "authority_conflict"
    elif truth == "REFUTED":
        verdict, reason = "INVALID", "same_subject_refutation"
    elif app == "ADMISSIBLE":
        verdict, reason = "VALID", "historical_evidence_admitted"
    elif app == "INADMISSIBLE":
        verdict, reason = "REVALIDATION_REQUIRED", "historical_evidence_inadmissible"
    else:
        verdict, reason = "UNRESOLVED", "historical_applicability_unadjudicated"

    return TransportAdjudicationVerdict(
        case_id=checked.case_id,
        verdict=verdict,
        reason_code=reason,
        adjudicated_historical_applicability=app != "UNDETERMINED",
        adjudicated_target_truth=truth != "UNKNOWN",
    )
