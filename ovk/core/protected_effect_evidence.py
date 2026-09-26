"""Sealed evidence and strict reuse checks for Protected Effect Integrity."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from ovk.core.bundle import content_digest
from ovk.core.evidence_integrity import (
    seal_evidence,
    verify_evidence_digest,
    verify_evidence_signature,
)
from ovk.core.incremental_assurance import protected_effect_semantic_digest
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus
from ovk.core.protected_effect_evaluation import ProtectedEffectIntegrityEvaluation
from ovk.core.assurance_ir import AssuranceIR


PE_CHECKER_ID = "protected-effect-integrity"
PE_CHECKER_VERSION = "0.1.0"
PE_GUARANTEE = "protected_effect_integrity.v1"


class EvidenceReuseContext(BaseModel):
    """Current execution context that cached evidence must match exactly."""

    semantic_slice_digest: str
    checker_id: str = PE_CHECKER_ID
    checker_version: str = PE_CHECKER_VERSION
    environment_digest: str
    policy_digest: str
    configuration_digest: str
    accepted_guarantee: str = PE_GUARANTEE


class EvidenceReuseDecision(BaseModel):
    reusable: bool
    reason: str


def _status(status: str) -> VerificationStatus:
    return {
        "pass": VerificationStatus.PASS,
        "fail": VerificationStatus.FAIL,
        "unknown": VerificationStatus.UNKNOWN,
    }.get(status, VerificationStatus.UNKNOWN)


def _subchecker_artifacts(
    evaluation: ProtectedEffectIntegrityEvaluation,
) -> list[dict]:
    rows = []
    for item in evaluation.resource_binding_evidence:
        rows.append(
            {
                "binding_id": item.binding_id,
                "checker_id": item.checker_id,
                "checker_version": item.checker_version,
                "native_execution": item.native_execution,
                "status": item.status,
            }
        )
    return rows


def protected_effect_evaluation_to_evidence(
    ir: AssuranceIR,
    evaluation: ProtectedEffectIntegrityEvaluation,
    *,
    environment_digest: str,
    policy_digest: str,
    configuration_digest: str | None = None,
    signing_key: bytes | None = None,
) -> VerificationEvidence:
    """Convert one evaluation into sealed, non-controlling OVK evidence."""

    semantic_digest = protected_effect_semantic_digest(
        ir,
        evaluation.protected_effect_id,
    )
    config_digest = configuration_digest or content_digest(
        {
            "checker_id": PE_CHECKER_ID,
            "checker_version": PE_CHECKER_VERSION,
            "extractor": ir.extractor.model_dump(mode="json"),
        }
    )
    backend_claim = BackendClaim(
        backend=PE_CHECKER_ID,
        guarantee_type=PE_GUARANTEE,
        status=_status(evaluation.status),
        assumptions=evaluation.assumptions,
        limits=[
            "Evidence is non-controlling shadow assurance.",
            "PASS requires complete extraction coverage.",
            "Resource-binding claims are limited to the explicit v1 identity model.",
        ],
        adapter_version=PE_CHECKER_VERSION,
        required=False,
    )

    counterexamples = [
        {
            "binding_id": item.binding_id,
            "counterexample": item.counterexample,
        }
        for item in evaluation.resource_binding_evidence
        if item.counterexample is not None
    ]

    evidence = VerificationEvidence(
        evidence_id="pe:" + content_digest(
            {
                "semantic_slice_digest": semantic_digest,
                "evaluation": evaluation.model_dump(mode="json"),
                "environment_digest": environment_digest,
                "policy_digest": policy_digest,
                "configuration_digest": config_digest,
            }
        )[:24],
        schema_version="ovk.evidence.v3",
        subject=ir.subject.model_dump(mode="json"),
        intent={
            "intent_id": "protected_effect_integrity",
            "protected_effect_id": evaluation.protected_effect_id,
            "assurance_ir_digest": evaluation.assurance_ir_digest,
        },
        backend_claims=[backend_claim],
        decision={
            "decision_state": "needs_review",
            "merge_recommendation": "require_human_review",
            "controlling": False,
            "reason": "shadow semantic assurance evidence; not merge-authoritative",
        },
        counterexamples=counterexamples,
        generated_artifacts=[
            {
                "kind": "protected_effect_evaluation",
                "evaluation": evaluation.model_dump(mode="json"),
            },
            {
                "kind": "protected_effect_semantic_slice",
                "protected_effect_id": evaluation.protected_effect_id,
                "semantic_slice_digest": semantic_digest,
            },
            {
                "kind": "subchecker_provenance",
                "checks": _subchecker_artifacts(evaluation),
            },
            {
                "kind": "execution_environment",
                "environment_digest": environment_digest,
            },
        ],
        coverage={
            "status": evaluation.extraction_coverage,
            "unknowns": (
                [] if evaluation.extraction_coverage == "complete"
                else [f"coverage status is {evaluation.extraction_coverage}"]
            ),
        },
        policy_digest=policy_digest,
        configuration_digest=config_digest,
    )

    return seal_evidence(
        evidence,
        key=signing_key,
        configuration_digest=config_digest,
        policy_digest=policy_digest,
        relevant_file_digests=[],
    )


def _artifact(evidence: VerificationEvidence, kind: str) -> dict | None:
    matches = [
        item
        for item in evidence.generated_artifacts
        if item.get("kind") == kind
    ]
    return matches[0] if len(matches) == 1 else None


def protected_effect_evidence_reuse_decision(
    evidence: VerificationEvidence,
    context: EvidenceReuseContext,
    *,
    signing_key: bytes | None = None,
) -> EvidenceReuseDecision:
    """Return reusable only under exact semantic and provenance equivalence."""

    if evidence.schema_version != "ovk.evidence.v3":
        return EvidenceReuseDecision(reusable=False, reason="unsupported_evidence_schema")
    if not verify_evidence_digest(evidence):
        return EvidenceReuseDecision(reusable=False, reason="invalid_evidence_digest")
    if evidence.signature is None:
        return EvidenceReuseDecision(reusable=False, reason="unsigned_evidence")
    if not verify_evidence_signature(evidence, key=signing_key):
        return EvidenceReuseDecision(reusable=False, reason="invalid_evidence_signature")

    if evidence.checker_id != context.checker_id:
        return EvidenceReuseDecision(reusable=False, reason="checker_id_mismatch")
    if evidence.checker_version != context.checker_version:
        return EvidenceReuseDecision(reusable=False, reason="checker_version_mismatch")
    if evidence.policy_digest != context.policy_digest:
        return EvidenceReuseDecision(reusable=False, reason="policy_digest_mismatch")
    if evidence.configuration_digest != context.configuration_digest:
        return EvidenceReuseDecision(reusable=False, reason="configuration_digest_mismatch")

    claims = [
        claim for claim in evidence.backend_claims
        if claim.guarantee_type == context.accepted_guarantee
    ]
    if len(claims) != 1:
        return EvidenceReuseDecision(reusable=False, reason="guarantee_mismatch")
    if claims[0].status != VerificationStatus.PASS:
        return EvidenceReuseDecision(reusable=False, reason="prior_evidence_not_pass")

    semantic = _artifact(evidence, "protected_effect_semantic_slice")
    if semantic is None:
        return EvidenceReuseDecision(reusable=False, reason="semantic_slice_artifact_missing")
    if semantic.get("semantic_slice_digest") != context.semantic_slice_digest:
        return EvidenceReuseDecision(reusable=False, reason="semantic_slice_mismatch")

    environment = _artifact(evidence, "execution_environment")
    if environment is None:
        return EvidenceReuseDecision(reusable=False, reason="environment_artifact_missing")
    if environment.get("environment_digest") != context.environment_digest:
        return EvidenceReuseDecision(reusable=False, reason="environment_digest_mismatch")

    subchecker = _artifact(evidence, "subchecker_provenance")
    if subchecker is None:
        return EvidenceReuseDecision(reusable=False, reason="subchecker_provenance_missing")
    for check in subchecker.get("checks") or []:
        if check.get("checker_id") == "z3" and not check.get("checker_version"):
            return EvidenceReuseDecision(reusable=False, reason="z3_version_missing")

    return EvidenceReuseDecision(reusable=True, reason="exact_semantic_and_provenance_match")
