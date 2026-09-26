"""Sealed evidence projection for Protected Effect Integrity evaluations.

This module intentionally emits shadow/non-controlling evidence. The candidate
claim status is preserved, but evidence maturity does not authorize ALLOW or
BLOCK until the source profile is separately qualified.
"""

from __future__ import annotations

from ovk.core.bundle import content_digest
from ovk.core.evidence_integrity import seal_evidence
from ovk.core.incremental_assurance import (
    protected_effect_semantic_digest,
    protected_effect_semantic_slice,
)
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus
from ovk.core.protected_effect_evaluation import ProtectedEffectIntegrityEvaluation


_CHECKER_ID = "ovk.protected_effect_integrity.v1"
_CHECKER_VERSION = "0.1.0"
_GUARANTEE = "protected_effect_integrity_advisory"


_STATUS_MAP: dict[str, VerificationStatus] = {
    "pass": VerificationStatus.PASS,
    "fail": VerificationStatus.FAIL,
    "unknown": VerificationStatus.UNKNOWN,
}


def _subchecker_artifacts(
    evaluation: ProtectedEffectIntegrityEvaluation,
) -> list[dict]:
    artifacts: list[dict] = []
    seen: set[tuple[str, str | None, str | None, bool | None]] = set()
    for item in evaluation.resource_binding_evidence:
        if item.checker_id is None:
            continue
        key = (
            item.checker_id,
            item.checker_version,
            item.tool_version,
            item.native_execution,
        )
        if key in seen:
            continue
        seen.add(key)
        artifacts.append(
            {
                "kind": "protected_effect_subchecker_provenance",
                "checker_id": item.checker_id,
                "checker_version": item.checker_version,
                "tool_version": item.tool_version,
                "native_execution": item.native_execution,
            }
        )
    return artifacts


def protected_effect_evaluation_to_evidence(
    ir,
    evaluation: ProtectedEffectIntegrityEvaluation,
    *,
    policy_digest: str | None = None,
    configuration_digest: str | None = None,
    signing_key: bytes | None = None,
) -> VerificationEvidence:
    """Build and seal non-controlling evidence for one Protected Effect result."""

    if evaluation.assurance_ir_digest != ir.assurance_ir_digest:
        raise ValueError(
            "protected-effect evaluation Assurance IR digest does not match supplied IR"
        )

    represented = {
        effect.protected_effect_id
        for effect in ir.protected_effects
    }
    if evaluation.protected_effect_id not in represented:
        raise ValueError(
            f"evaluation references unknown protected effect: {evaluation.protected_effect_id}"
        )

    semantic_slice = protected_effect_semantic_slice(
        ir,
        evaluation.protected_effect_id,
    )
    semantic_digest = protected_effect_semantic_digest(
        ir,
        evaluation.protected_effect_id,
    )
    status = _STATUS_MAP.get(evaluation.status, VerificationStatus.UNKNOWN)

    # A compact content-addressed material binds evidence input to the exact
    # semantic slice, while the complete slice remains an inspectable artifact.
    material = {
        "material_id": content_digest(
            {
                "protected_effect_id": evaluation.protected_effect_id,
                "semantic_digest": semantic_digest,
            }
        )[:32],
        "kind": "generated_harness",
        "uri": (
            "ovk-material:protected-effect/"
            + evaluation.protected_effect_id
        ),
        "sha256": semantic_digest,
        "size_bytes": len(str(semantic_slice).encode("utf-8")),
        "source_revision": ir.subject.head_sha,
        "trusted": True,
    }

    source_profile_id = ir.extractor.source_profile_id or ir.extractor.extractor_id
    evidence_id = "ev-pei-" + content_digest(
        {
            "semantic_digest": semantic_digest,
            "status": evaluation.status,
            "checker_id": _CHECKER_ID,
            "checker_version": _CHECKER_VERSION,
        }
    )[:24]

    subchecker_artifacts = _subchecker_artifacts(evaluation)

    generated_artifacts = [
        {
            "kind": "protected_effect_evaluation",
            "evaluation": evaluation.model_dump(mode="json"),
        },
        {
            "kind": "protected_effect_semantic_slice",
            "semantic_digest": semantic_digest,
            "slice": semantic_slice,
        },
        {
            "kind": "source_profile_maturity",
            "source_profile_id": source_profile_id,
            "maturity": "executable_advisory",
            "controlling": False,
            "reason": (
                "candidate Protected Effect source profile is not yet "
                "attested/calibrated for controlling merge decisions"
            ),
        },
        *subchecker_artifacts,
    ]

    subject = {
        "repo": ir.subject.repo,
        "head_sha": ir.subject.head_sha,
    }
    if ir.subject.base_sha is not None:
        subject["base_sha"] = ir.subject.base_sha
    if ir.subject.pull_request is not None:
        subject["pull_request"] = ir.subject.pull_request

    evidence = VerificationEvidence(
        evidence_id=evidence_id,
        schema_version="ovk.evidence.v3",
        subject=subject,
        intent={
            "intent_id": "protected_effect_integrity",
            "version": "0.1.0",
            "title": "Protected Effect Integrity",
            "source_profile_id": source_profile_id,
            "protected_effect_id": evaluation.protected_effect_id,
            "semantic_slice_digest": semantic_digest,
            "risk": {"severity": "high"},
        },
        backend_claims=[
            BackendClaim(
                backend=_CHECKER_ID,
                guarantee_type=_GUARANTEE,
                status=status,
                assumptions=list(evaluation.assumptions),
                limits=[
                    "This evidence is advisory and non-controlling.",
                    "Source-to-Assurance-IR extraction soundness is a separate obligation.",
                    "Resource-binding sub-checkers are recorded in generated artifacts.",
                    "A PASS does not imply full application correctness.",
                ],
                adapter_version=_CHECKER_VERSION,
                required=False,
            )
        ],
        decision={
            "decision_state": "needs_review",
            "original_decision_state": "needs_review",
            "merge_recommendation": "require_human_review",
            "candidate_claim_status": evaluation.status,
            "controlling": False,
            "controlling_finding_ids": [],
            "finding_contributions": [
                {
                    "finding_id": f"{evidence_id}:candidate",
                    "claim_status": evaluation.status,
                    "required": False,
                    "contribution": "non_controlling",
                    "detail": evaluation.reason,
                }
            ],
            "reason": (
                "Protected Effect Integrity result is shadow evidence pending "
                "source-profile qualification"
            ),
        },
        change_origin={
            "author_type": "ovk_semantic_evaluator",
            "agent": _CHECKER_ID,
            "task": "protected_effect_integrity",
        },
        generated_artifacts=generated_artifacts,
        materials=[material],
        material_set_digest=None,
        coverage={
            "status": evaluation.extraction_coverage,
            "confidence": ir.coverage.confidence,
            "unknowns": list(ir.coverage.unsupported_constructs),
        },
        compiler={
            "compiler_id": ir.extractor.extractor_id,
            "compiler_version": ir.extractor.extractor_version,
            "source_profile_id": source_profile_id,
        },
        aggregation_policy="shadow_non_controlling.v1",
        routing_enforced=False,
    )

    sealed = seal_evidence(
        evidence,
        key=signing_key,
        configuration_digest=(
            configuration_digest
            or content_digest(
                {
                    "checker_id": _CHECKER_ID,
                    "checker_version": _CHECKER_VERSION,
                    "source_profile_id": source_profile_id,
                    "extractor": ir.extractor.model_dump(mode="json"),
                    "subcheckers": subchecker_artifacts,
                }
            )
        ),
        policy_digest=(
            policy_digest
            or content_digest(
                {
                    "policy": "shadow_non_controlling.v1",
                    "guarantee": _GUARANTEE,
                }
            )
        ),
    )

    # seal_evidence derives input_digest from materials. Ensure the material is
    # still bound to the exact semantic slice before returning.
    material_digest = sealed.materials[0]["sha256"] if sealed.materials else None
    if material_digest != semantic_digest:
        raise ValueError("sealed Protected Effect evidence lost semantic-slice binding")
    return sealed
