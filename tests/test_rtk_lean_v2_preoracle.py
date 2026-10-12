"""Development-only blinding tests, without fabricated native checker outcomes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from experiments.rtk.adjudication_v2 import (
    ExternalWitnessRecord,
    TransportAdjudicationInput,
)
from experiments.rtk.lean_v2_preoracle import (
    FrozenCohort,
    FrozenLeanCase,
    OracleBatch,
    Prediction,
    PredictionBundle,
    make_commitment,
    digest,
    score_provisional,
)


A, B, C, D, E = ("a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64)
NONCE = "09" * 32
SHA1, SHA2, SHA3, SHA4 = ("1" * 40, "2" * 40, "3" * 40, "4" * 40)


def case(i: int, *, path: str = "Proof.lean") -> FrozenLeanCase:
    return FrozenLeanCase(
        case_id=f"C{i}",
        transition_id=f"T{i}",
        repository="external/lean-examples",
        source_sha=SHA1 if i == 0 else SHA3,
        target_sha=SHA2 if i == 0 else SHA4,
        source_path=path,
        target_path=path,
        theorem_name="example_theorem",
        source_evidence_sha256=A,
        source_native_acceptance_sha256=B,
        source_context_sha256=C,
        target_claim_sha256=D,
        target_context_sha256=E,
        selection_rank=i,
    )


def build_cohort(n: int = 2) -> FrozenCohort:
    return FrozenCohort(
        schema_version="rtk.lean_v2.preoracle_cohort.v1",
        selection_rule_sha256="f" * 64,
        source_adapter_id="lean-source@v2",
        oracle_adapter_id="native-term-replay@v2",
        cases=[case(i) for i in range(n)],
    )


def build_predictions(cohort: FrozenCohort) -> PredictionBundle:
    return PredictionBundle(
        schema_version="rtk.lean_v2.predictions.v1",
        cohort_sha256=digest(cohort),
        sut_commit=SHA1,
        sut_adapter_id="independent-lean-sut@draft",
        predictions=[
            Prediction(
                case_id=case_item.case_id,
                input_sha256=digest(case_item),
                verdict="VALID",
            )
            for case_item in cohort.cases
        ],
    )


def witness(kind: str, *, source: str | None = A) -> ExternalWitnessRecord:
    return ExternalWitnessRecord(
        kind=kind,
        verifier_identity="native-lean@reproducible",
        checker_invocation_sha256=B,
        artifact_sha256=C,
        target_claim_sha256=D,
        target_context_sha256=E,
        source_evidence_sha256=source,
    )


def observation(case_id: str, *, app: str, truth: str) -> TransportAdjudicationInput:
    return TransportAdjudicationInput(
        schema_version="rtk.adjudication.v2-development",
        case_id=case_id,
        source_evidence_sha256=A,
        target_claim_sha256=D,
        target_context_sha256=E,
        target_claim_status=truth,
        historical_evidence_applicability=app,
        applicability_witness=(
            witness("EXACT_CERTIFICATE_REPLAY") if app == "ADMISSIBLE"
            else witness("EXPLICIT_INAPPLICABILITY") if app == "INADMISSIBLE"
            else None
        ),
        target_establishment_witness=(
            witness("TARGET_NATIVE_ESTABLISHMENT", source=None)
            if truth == "ESTABLISHED" else None
        ),
    )


def test_exact_case_bound_commitment_and_provisional_counts():
    cohort = build_cohort()
    preds = build_predictions(cohort)
    receipt = make_commitment(cohort, preds, private_nonce_hex=NONCE)
    oracle = OracleBatch(
        schema_version="rtk.lean_v2.oracle_batch.v1",
        cohort_sha256=digest(cohort),
        observations=[
            observation("C0", app="ADMISSIBLE", truth="UNKNOWN"),
            observation("C1", app="INADMISSIBLE", truth="ESTABLISHED"),
        ],
    )
    score = score_provisional(cohort, preds, receipt, NONCE, oracle)
    assert score.total_cases == 2
    assert score.resolved_cases == 2
    assert score.confirmed_nonvalid_cases == 1
    assert score.falsely_reused_nonvalid_cases == 1
    assert score.confirmed_valid_cases == 1
    assert score.unadjudicated_valid_predictions == 0
    assert score.evidence_status == "PROVISIONAL_UNAUDITED"
    assert score.independent_oracle_execution_verified is False
    assert score.chronological_precommitment_verified is False


def test_fresh_target_pass_does_not_resolve_historical_reuse():
    cohort = build_cohort(1)
    preds = build_predictions(cohort)
    receipt = make_commitment(cohort, preds, private_nonce_hex=NONCE)
    oracle = OracleBatch(
        schema_version="rtk.lean_v2.oracle_batch.v1",
        cohort_sha256=digest(cohort),
        observations=[observation("C0", app="UNDETERMINED", truth="ESTABLISHED")],
    )
    score = score_provisional(cohort, preds, receipt, NONCE, oracle)
    assert score.resolved_cases == 0
    assert score.unresolved_cases == 1
    assert score.unadjudicated_valid_predictions == 1


def test_nonce_is_required_and_commitment_changes_with_nonce():
    cohort = build_cohort(1)
    preds = build_predictions(cohort)
    with pytest.raises(ValueError, match="nonce"):
        make_commitment(cohort, preds, private_nonce_hex="0000")
    a = make_commitment(cohort, preds, private_nonce_hex=NONCE)
    b = make_commitment(cohort, preds, private_nonce_hex="0a" * 32)
    assert a.commitment_sha256 != b.commitment_sha256
    assert NONCE not in a.model_dump_json()


def test_reject_changed_predictions_and_mismatched_commitment():
    cohort = build_cohort(1)
    preds = build_predictions(cohort)
    receipt = make_commitment(cohort, preds, private_nonce_hex=NONCE)
    wrong = PredictionBundle(
        schema_version=preds.schema_version,
        cohort_sha256=preds.cohort_sha256,
        sut_commit=preds.sut_commit,
        sut_adapter_id=preds.sut_adapter_id,
        predictions=[
            Prediction(case_id="C0", input_sha256=digest(case(0)),
                       verdict="REVALIDATION_REQUIRED"),
        ],
    )
    oracle = OracleBatch(
        schema_version="rtk.lean_v2.oracle_batch.v1",
        cohort_sha256=digest(cohort),
        observations=[observation("C0", app="ADMISSIBLE", truth="UNKNOWN")],
    )
    with pytest.raises(ValueError, match="commitment"):
        score_provisional(cohort, wrong, receipt, NONCE, oracle)
    with pytest.raises(ValueError, match="commitment"):
        score_provisional(cohort, preds, receipt, "0a" * 32, oracle)


def test_reject_oracle_order_old_evidence_or_context_mismatch():
    cohort = build_cohort(2)
    preds = build_predictions(cohort)
    receipt = make_commitment(cohort, preds, private_nonce_hex=NONCE)
    swapped = OracleBatch(
        schema_version="rtk.lean_v2.oracle_batch.v1",
        cohort_sha256=digest(cohort),
        observations=[
            observation("C1", app="ADMISSIBLE", truth="UNKNOWN"),
            observation("C0", app="ADMISSIBLE", truth="UNKNOWN"),
        ],
    )
    with pytest.raises(ValueError, match="oracle case order"):
        score_provisional(cohort, preds, receipt, NONCE, swapped)

    obs = observation("C0", app="ADMISSIBLE", truth="UNKNOWN")
    forged = obs.model_copy(update={"source_evidence_sha256": "9" * 64})
    bad = OracleBatch(
        schema_version="rtk.lean_v2.oracle_batch.v1",
        cohort_sha256=digest(build_cohort(1)),
        observations=[forged],
    )
    one = build_cohort(1)
    one_preds = build_predictions(one)
    one_receipt = make_commitment(one, one_preds, private_nonce_hex=NONCE)
    with pytest.raises(ValueError, match="oracle claim, context"):
        score_provisional(one, one_preds, one_receipt, NONCE, bad)


def test_source_case_disallows_path_traversal_and_internal_repositories():
    with pytest.raises(ValidationError, match="path"):
        case(0, path="../secrets.lean")
    with pytest.raises(ValidationError):
        case(0).model_copy(update={"repository": "fraware/sut"}).model_dump()
    # model_copy deliberately bypasses validation, so the trust boundary
    # must revalidate prior to accepting a supplied cohort.


def test_reject_duplicate_cases_and_changed_case_order():
    cohort = build_cohort(2)
    with pytest.raises(ValidationError, match="duplicate case ID"):
        FrozenCohort.model_validate({
            **cohort.model_dump(),
            "cases": [case(0).model_dump(), case(0).model_dump()],
        })
    preds = build_predictions(cohort)
    swapped = PredictionBundle(
        **{**preds.model_dump(),
           "predictions": list(reversed(preds.model_dump()["predictions"]))}
    )
    with pytest.raises(ValueError, match="prediction case order"):
        make_commitment(cohort, swapped, private_nonce_hex=NONCE)


def test_stored_models_cannot_add_sut_prediction_to_native_oracle():
    cohort = build_cohort(1)
    oracle_data = {
        "schema_version": "rtk.lean_v2.oracle_batch.v1",
        "cohort_sha256": digest(cohort),
        "observations": [
            {**observation("C0", app="ADMISSIBLE", truth="UNKNOWN").model_dump(),
             "sut_prediction": "VALID"}
        ],
    }
    with pytest.raises(ValidationError):
        OracleBatch.model_validate(oracle_data)


def test_private_commitment_receipt_is_canonical_json():
    cohort = build_cohort(1)
    preds = build_predictions(cohort)
    receipt = make_commitment(cohort, preds, private_nonce_hex=NONCE)
    reread = type(receipt).model_validate_json(receipt.model_dump_json())
    assert reread == receipt
    assert len(receipt.commitment_sha256) == 64
    assert json.loads(receipt.model_dump_json())["prediction_count"] == 1
