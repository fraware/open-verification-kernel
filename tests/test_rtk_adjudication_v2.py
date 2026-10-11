"""Development-only tests of RTK two-axis adjudication; no native oracle runs."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from experiments.rtk.adjudication_v2 import (
    ExternalWitnessRecord,
    TransportAdjudicationInput,
    derive_transport_verdict,
)


SOURCE = "a" * 64
CLAIM = "b" * 64
CONTEXT = "c" * 64
ARTIFACT = "d" * 64
INVOCATION = "e" * 64


def _witness(kind: str, *, source: str | None = None):
    return ExternalWitnessRecord(
        kind=kind,
        verifier_identity="independent-native-checker@pinned",
        checker_invocation_sha256=INVOCATION,
        artifact_sha256=ARTIFACT,
        target_claim_sha256=CLAIM,
        target_context_sha256=CONTEXT,
        source_evidence_sha256=source,
    )


def _record(
    *,
    truth="UNKNOWN",
    applicability="UNDETERMINED",
    source_witness=None,
    establishment=None,
    refutation=None,
    failure=None,
):
    return TransportAdjudicationInput(
        schema_version="rtk.adjudication.v2-development",
        case_id="develop-case-1",
        source_evidence_sha256=SOURCE,
        target_claim_sha256=CLAIM,
        target_context_sha256=CONTEXT,
        target_claim_status=truth,
        historical_evidence_applicability=applicability,
        applicability_witness=source_witness,
        target_establishment_witness=establishment,
        target_refutation_witness=refutation,
        operational_failure=failure,
    )


@pytest.mark.parametrize(
    ("truth", "app", "witness_kind", "verdict", "reason"),
    [
        ("UNKNOWN", "ADMISSIBLE", "EXACT_CERTIFICATE_REPLAY",
         "VALID", "historical_evidence_admitted"),
        ("ESTABLISHED", "ADMISSIBLE", "INDEPENDENT_SEMANTIC_CONTINUITY",
         "VALID", "historical_evidence_admitted"),
        ("UNKNOWN", "INADMISSIBLE", "EXPLICIT_INAPPLICABILITY",
         "REVALIDATION_REQUIRED", "historical_evidence_inadmissible"),
        ("ESTABLISHED", "INADMISSIBLE", "EXPLICIT_INAPPLICABILITY",
         "REVALIDATION_REQUIRED", "historical_evidence_inadmissible"),
        ("REFUTED", "INADMISSIBLE", "EXPLICIT_INAPPLICABILITY",
         "INVALID", "same_subject_refutation"),
        ("REFUTED", "UNDETERMINED", None,
         "INVALID", "same_subject_refutation"),
        ("REFUTED", "ADMISSIBLE", "EXACT_CERTIFICATE_REPLAY",
         "UNRESOLVED", "authority_conflict"),
        ("ESTABLISHED", "UNDETERMINED", None,
         "UNRESOLVED", "historical_applicability_unadjudicated"),
        ("UNKNOWN", "UNDETERMINED", None,
         "UNRESOLVED", "historical_applicability_unadjudicated"),
    ],
)
def test_all_adjudication_axes(truth, app, witness_kind, verdict, reason):
    source_witness = (
        _witness(witness_kind, source=SOURCE)
        if witness_kind is not None else None
    )
    establishment = (
        _witness("TARGET_NATIVE_ESTABLISHMENT")
        if truth == "ESTABLISHED" else None
    )
    refutation = (
        _witness("SAME_SUBJECT_REFUTATION")
        if truth == "REFUTED" else None
    )
    record = _record(
        truth=truth,
        applicability=app,
        source_witness=source_witness,
        establishment=establishment,
        refutation=refutation,
    )
    result = derive_transport_verdict(record)
    assert result.verdict == verdict
    assert result.reason_code == reason
    assert result.adjudicated_historical_applicability == (app != "UNDETERMINED")
    assert result.adjudicated_target_truth == (truth != "UNKNOWN")


def test_fresh_target_pass_cannot_launder_old_evidence_into_valid():
    record = _record(
        truth="ESTABLISHED",
        establishment=_witness("TARGET_NATIVE_ESTABLISHMENT"),
    )
    assert derive_transport_verdict(record).verdict == "UNRESOLVED"


def test_replay_timeout_is_unresolved():
    record = _record(failure="historical prover timed out")
    result = derive_transport_verdict(record)
    assert result.verdict == "UNRESOLVED"
    assert result.reason_code == "operational_failure"


@pytest.mark.parametrize(
    "changes",
    [
        {"historical_evidence_applicability": "ADMISSIBLE"},
        {"historical_evidence_applicability": "INADMISSIBLE"},
        {"target_claim_status": "ESTABLISHED"},
        {"target_claim_status": "REFUTED"},
        {
            "historical_evidence_applicability": "ADMISSIBLE",
            "applicability_witness": _witness(
                "TARGET_NATIVE_ESTABLISHMENT", source=SOURCE
            ),
        },
        {
            "historical_evidence_applicability": "INADMISSIBLE",
            "applicability_witness": _witness(
                "EXACT_CERTIFICATE_REPLAY", source=SOURCE
            ),
        },
        {
            "historical_evidence_applicability": "ADMISSIBLE",
            "applicability_witness": _witness(
                "EXACT_CERTIFICATE_REPLAY", source="f" * 64
            ),
        },
        {"target_refutation_witness": _witness("SAME_SUBJECT_REFUTATION")},
        {"operational_failure": "timeout", "target_claim_status": "ESTABLISHED"},
        {"source_evidence_sha256": "too-short"},
    ],
)
def test_missing_incompatible_or_mismatched_witnesses_fail_closed(changes):
    data = _record().model_dump()
    data.update(changes)
    with pytest.raises(ValidationError):
        TransportAdjudicationInput.model_validate(data)


def test_target_context_and_statement_witness_identity_is_checked():
    witness = _witness("EXACT_CERTIFICATE_REPLAY", source=SOURCE)
    bad = witness.model_copy(update={"target_context_sha256": "f" * 64})
    with pytest.raises(ValidationError, match="target claim/context"):
        _record(applicability="ADMISSIBLE", source_witness=bad)


def test_no_sut_prediction_field_allowed_in_adjudication_data():
    data = _record().model_dump()
    data["sut_prediction"] = "VALID"
    with pytest.raises(ValidationError):
        TransportAdjudicationInput.model_validate(data)


def test_normalizer_rechecks_model_copy_without_validation():
    record = _record()
    forged = record.model_copy(
        update={"historical_evidence_applicability": "ADMISSIBLE"}
    )
    with pytest.raises(ValidationError):
        derive_transport_verdict(forged)


def test_operational_failure_cannot_hide_decisive_native_witness():
    with pytest.raises(ValidationError):
        _record(
            failure="timeout",
            truth="REFUTED",
            refutation=_witness("SAME_SUBJECT_REFUTATION"),
        )
