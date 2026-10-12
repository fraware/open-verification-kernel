"""Sealed pre-oracle case/prediction/scoring protocol for prospective RTK v2.

This module protects *record identity* and verifies a high-entropy prediction
commitment. It cannot prove a native checker was run, authenticate a purported
witness, enforce independent process permissions, or reconstruct a Git push
timestamp. All quantitative outputs are PROVISIONAL until those independent
assumptions are audited. It does not evaluate a Lean RTK SUT.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from experiments.rtk.adjudication_v2 import (
    TransportAdjudicationInput,
    derive_transport_verdict,
)

_SHA = r"^[0-9a-f]{64}$"
_GIT_SHA = r"^[0-9a-f]{40}$"
_REPO = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
_PREDICTION = Literal["VALID", "INVALID", "REVALIDATION_REQUIRED", "UNRESOLVED"]
_DOMAIN = b"ovk.rtk.v2.prediction-commitment.v1" + bytes([0])


def canonical_bytes(value: BaseModel) -> bytes:
    """Deterministic JSON encoding for exact, typed payloads."""
    return json.dumps(
        value.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def digest(value: BaseModel) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


class FrozenLeanCase(BaseModel):
    """Pre-oracle claim identity; digest fields are asserted, not authenticated."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1)
    transition_id: str = Field(min_length=1)
    repository: str = Field(pattern=_REPO)
    source_sha: str = Field(pattern=_GIT_SHA)
    target_sha: str = Field(pattern=_GIT_SHA)
    source_path: str = Field(min_length=1)
    target_path: str = Field(min_length=1)
    theorem_name: str = Field(min_length=1)
    source_evidence_sha256: str = Field(pattern=_SHA)
    source_native_acceptance_sha256: str = Field(pattern=_SHA)
    source_context_sha256: str = Field(pattern=_SHA)
    target_claim_sha256: str = Field(pattern=_SHA)
    target_context_sha256: str = Field(pattern=_SHA)
    selection_rank: int = Field(ge=0)

    @field_validator("source_path", "target_path")
    @classmethod
    def path_is_restricted(cls, value: str) -> str:
        components = value.split("/")
        if (
            value.startswith("/")
            or chr(92) in value
            or any(part in ("", ".", "..") for part in components)
            or not value.endswith(".lean")
        ):
            raise ValueError("invalid relative Lean source path")
        return value

    @model_validator(mode="after")
    def validate_identity(self) -> "FrozenLeanCase":
        if self.source_sha == self.target_sha:
            raise ValueError("source and target commits must differ")
        if self.repository.lower().startswith(("fraware/", "sentinelops-ci/")):
            raise ValueError("internal repositories are ineligible for external corpus")
        return self


class FrozenCohort(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["rtk.lean_v2.preoracle_cohort.v1"]
    selection_rule_sha256: str = Field(pattern=_SHA)
    source_adapter_id: str = Field(min_length=1)
    oracle_adapter_id: str = Field(min_length=1)
    oracle_commit: str = Field(pattern=_GIT_SHA)
    sut_adapter_id: str = Field(min_length=1)
    sut_commit: str = Field(pattern=_GIT_SHA)
    cases: list[FrozenLeanCase] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_case_set(self) -> "FrozenCohort":
        ids = [case.case_id for case in self.cases]
        ranks = [case.selection_rank for case in self.cases]
        transitions = [case.transition_id for case in self.cases]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate case ID")
        if len(set(ranks)) != len(ranks) or sorted(ranks) != list(range(len(ranks))):
            raise ValueError("case ranks must cover 0 through N-1")
        if len(set(transitions)) != len(transitions):
            raise ValueError("multiple claims per transition need a separate cluster rule")
        if ranks != sorted(ranks):
            raise ValueError("case order must match frozen selection rank")
        return self


class Prediction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1)
    input_sha256: str = Field(pattern=_SHA)
    verdict: _PREDICTION


class PredictionBundle(BaseModel):
    """Only externally produced SUT predictions; no oracle information."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["rtk.lean_v2.predictions.v1"]
    cohort_sha256: str = Field(pattern=_SHA)
    sut_commit: str = Field(pattern=_GIT_SHA)
    sut_adapter_id: str = Field(min_length=1)
    predictions: list[Prediction] = Field(min_length=1)


class PredictionCommitment(BaseModel):
    """Public pre-oracle receipt; nonce and prediction inputs stay separate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["rtk.lean_v2.commitment.v1"]
    cohort_sha256: str = Field(pattern=_SHA)
    prediction_bundle_sha256: str = Field(pattern=_SHA)
    sut_commit: str = Field(pattern=_GIT_SHA)
    prediction_count: int = Field(ge=1)
    commitment_sha256: str = Field(pattern=_SHA)


def _validate_prediction_batch(cohort: FrozenCohort, batch: PredictionBundle) -> None:
    if batch.sut_commit != cohort.sut_commit:
        raise ValueError("SUT commit differs from frozen implementation identity")
    if batch.sut_adapter_id != cohort.sut_adapter_id:
        raise ValueError("SUT adapter differs from frozen implementation identity")
    if batch.cohort_sha256 != digest(cohort):
        raise ValueError("prediction batch refers to a different frozen cohort")
    if len(batch.predictions) != len(cohort.cases):
        raise ValueError("missing or extra prediction")
    for case, prediction in zip(cohort.cases, batch.predictions, strict=True):
        if case.case_id != prediction.case_id:
            raise ValueError("prediction case order or identity mismatch")
        # Prediction input digest is the exact pre-outcome case identity. It
        # binds target claim and context, with no native verdict included.
        if prediction.input_sha256 != digest(case):
            raise ValueError("prediction input differs from case identity")


def _nonce_bytes(nonce_hex: str) -> bytes:
    if len(nonce_hex) != 64:
        raise ValueError("private nonce must contain 32 random bytes")
    try:
        nonce = bytes.fromhex(nonce_hex)
    except ValueError as error:
        raise ValueError("invalid private nonce hex") from error
    if len(nonce) != 32:
        raise ValueError("invalid private nonce length")
    return nonce


def make_commitment(
    cohort: FrozenCohort,
    batch: PredictionBundle,
    *,
    private_nonce_hex: str,
) -> PredictionCommitment:
    """Commit before target oracle material is exposed.

    The nonce is never part of the public receipt. This method cannot itself
    prove that a later Git commit predates the native oracle run.
    """

    # Pydantic model_copy(update=...) bypasses validation. Reject externally
    # reconstructed instances at the public admission boundary.
    cohort = FrozenCohort.model_validate(cohort.model_dump(mode="json"))
    batch = PredictionBundle.model_validate(batch.model_dump(mode="json"))
    _validate_prediction_batch(cohort, batch)
    nonce = _nonce_bytes(private_nonce_hex)
    payload_digest = bytes.fromhex(digest(batch))
    seal = hashlib.sha256(
        _DOMAIN + bytes.fromhex(digest(cohort)) + nonce + payload_digest
    ).hexdigest()
    return PredictionCommitment(
        schema_version="rtk.lean_v2.commitment.v1",
        cohort_sha256=digest(cohort),
        prediction_bundle_sha256=digest(batch),
        sut_commit=batch.sut_commit,
        prediction_count=len(batch.predictions),
        commitment_sha256=seal,
    )


def _validate_commitment(
    cohort: FrozenCohort,
    batch: PredictionBundle,
    receipt: PredictionCommitment,
    nonce_hex: str,
) -> None:
    expected = make_commitment(cohort, batch, private_nonce_hex=nonce_hex)
    if not hmac.compare_digest(
        canonical_bytes(receipt), canonical_bytes(expected)
    ):
        raise ValueError("prediction commitment invalid or pre-oracle content changed")


class OracleBatch(BaseModel):
    """Submitted only by a separately controlled target-native adjudicator."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["rtk.lean_v2.oracle_batch.v1"]
    cohort_sha256: str = Field(pattern=_SHA)
    oracle_adapter_id: str = Field(min_length=1)
    oracle_commit: str = Field(pattern=_GIT_SHA)
    observations: list[TransportAdjudicationInput] = Field(min_length=1)


class ProvisionalScore(BaseModel):
    """Counts have no inferential or confirmation authority without external audit."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["rtk.lean_v2.provisional_score.v1"]
    evidence_status: Literal["PROVISIONAL_UNAUDITED"]
    independent_oracle_execution_verified: Literal[False] = False
    chronological_precommitment_verified: Literal[False] = False
    cohort_sha256: str
    prediction_bundle_sha256: str
    oracle_batch_sha256: str
    total_cases: int
    resolved_cases: int
    unresolved_cases: int
    resolved_nonvalid_labels: int
    valid_predictions_on_resolved_nonvalid_labels: int
    unadjudicated_valid_predictions: int
    resolved_valid_labels: int
    unnecessary_revalidations: int
    counts_by_predicted_verdict: dict[str, int]


def score_provisional(
    cohort: FrozenCohort,
    batch: PredictionBundle,
    receipt: PredictionCommitment,
    private_nonce_hex: str,
    oracle: OracleBatch,
) -> ProvisionalScore:
    """Check exact case/commitment identity and count observable disagreements.

    The scorer refuses partial oracle batches and unbound case identities.
    It never silently turns UNRESOLVED into an adjudicated success.
    """

    _validate_commitment(cohort, batch, receipt, private_nonce_hex)
    oracle = OracleBatch.model_validate(oracle.model_dump(mode="json"))
    if oracle.cohort_sha256 != digest(cohort):
        raise ValueError("oracle batch does not belong to frozen cohort")
    if (
        oracle.oracle_adapter_id != cohort.oracle_adapter_id
        or oracle.oracle_commit != cohort.oracle_commit
    ):
        raise ValueError("oracle implementation differs from frozen registration")
    if len(oracle.observations) != len(cohort.cases):
        raise ValueError("oracle omitted or added cases")
    resolved = nonvalid = false_reuse = unresolved_valid = valid = unnecessary = 0
    counts: dict[str, int] = {
        "VALID": 0, "INVALID": 0,
        "REVALIDATION_REQUIRED": 0, "UNRESOLVED": 0,
    }
    for case, pred, observation in zip(
        cohort.cases, batch.predictions, oracle.observations, strict=True
    ):
        if observation.case_id != case.case_id:
            raise ValueError("oracle case order or identity mismatch")
        if (
            observation.source_evidence_sha256 != case.source_evidence_sha256
            or observation.target_claim_sha256 != case.target_claim_sha256
            or observation.target_context_sha256 != case.target_context_sha256
        ):
            raise ValueError("oracle claim, context, or old evidence identity mismatch")
        verdict = derive_transport_verdict(observation).verdict
        counts[pred.verdict] += 1
        if verdict == "UNRESOLVED":
            if pred.verdict == "VALID":
                unresolved_valid += 1
            continue
        resolved += 1
        if verdict in {"INVALID", "REVALIDATION_REQUIRED"}:
            nonvalid += 1
            if pred.verdict == "VALID":
                false_reuse += 1
        elif verdict == "VALID":
            valid += 1
            if pred.verdict == "REVALIDATION_REQUIRED":
                unnecessary += 1
    return ProvisionalScore(
        schema_version="rtk.lean_v2.provisional_score.v1",
        evidence_status="PROVISIONAL_UNAUDITED",
        cohort_sha256=digest(cohort),
        prediction_bundle_sha256=digest(batch),
        oracle_batch_sha256=digest(oracle),
        total_cases=len(cohort.cases),
        resolved_cases=resolved,
        unresolved_cases=len(cohort.cases) - resolved,
        resolved_nonvalid_labels=nonvalid,
        valid_predictions_on_resolved_nonvalid_labels=false_reuse,
        unadjudicated_valid_predictions=unresolved_valid,
        resolved_valid_labels=valid,
        unnecessary_revalidations=unnecessary,
        counts_by_predicted_verdict=counts,
    )


def _load_json(path: Path, cls: type[BaseModel]) -> BaseModel:
    return cls.model_validate_json(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: BaseModel) -> None:
    # Intentional no-overwrite: changing a frozen record is a new experiment.
    with path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(
            value.model_dump(mode="json"), indent=2, sort_keys=True
        ) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="mode", required=True)
    for name in ("commit", "score"):
        cmd = subcommands.add_parser(name)
        cmd.add_argument("--cohort", type=Path, required=True)
        cmd.add_argument("--predictions", type=Path, required=True)
        cmd.add_argument("--receipt", type=Path, required=True)
        cmd.add_argument("--nonce-file", type=Path, required=True)
        if name == "score":
            cmd.add_argument("--oracle", type=Path, required=True)
            cmd.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cohort = _load_json(args.cohort, FrozenCohort)
    batch = _load_json(args.predictions, PredictionBundle)
    if args.mode == "commit":
        # Keep the nonce out of the current code tree so it cannot be
        # accidentally committed to a public branch. It is private until
        # the authorized single unblinding.
        if not args.nonce_file.is_absolute():
            parser.error("nonce-file must be an absolute private path")
        if args.nonce_file.resolve().is_relative_to(Path.cwd().resolve()):
            parser.error("nonce-file must be outside the current worktree")
        if args.receipt.exists() or args.nonce_file.exists():
            parser.error("frozen receipt or private nonce file already exists")
        nonce = secrets.token_bytes(32).hex()
        receipt = make_commitment(cohort, batch, private_nonce_hex=nonce)
        nonce_fd = os.open(
            args.nonce_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        try:
            with os.fdopen(nonce_fd, "w", encoding="ascii") as output:
                output.write(nonce + "\n")
            _write_json(args.receipt, receipt)
        except BaseException:
            args.nonce_file.unlink(missing_ok=True)
            raise
        print("PREDICTION_COMMITMENT_CREATED")
        return 0

    receipt = _load_json(args.receipt, PredictionCommitment)
    oracle = _load_json(args.oracle, OracleBatch)
    result = score_provisional(
        cohort, batch, receipt,
        args.nonce_file.read_text(encoding="ascii").strip(),
        oracle,
    )
    _write_json(args.output, result)
    print("PROVISIONAL_COUNTS_ONLY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
