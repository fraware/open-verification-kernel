"""Sealed Protected Effect evidence and strict cross-revision reuse.

Protected Effect evaluations are projected into ordinary VerificationEvidence
records. They remain shadow / non-controlling by default.

Cross-revision reuse is permitted only when a prior sealed PASS is:
- integrity-valid and supported;
- unrevoked and within its reuse horizon;
- for the same repository and protected effect;
- bound to the same semantic support slice;
- bound to the same policy digest;
- produced by the same Protected Effect checker version; and
- bound to an exactly matching execution fingerprint.

The execution fingerprint includes environment, tool, worker-image identity, and
the resource-binding checker engines actually observed during evaluation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator

from ovk import __version__ as OVK_VERSION
from ovk.core.assurance_ir import AssuranceIR
from ovk.core.bundle import content_digest
from ovk.core.evidence_integrity import (
    integrity_envelope_complete,
    is_supported_schema_version,
    recompute_input_digest,
    seal_evidence,
    verify_evidence_digest,
    verify_evidence_signature,
)
from ovk.core.incremental_assurance import protected_effect_semantic_digest
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus
from ovk.core.protected_effect_evaluation import ProtectedEffectIntegrityEvaluation
from ovk.core.result_cache import (
    HardenedResultCache,
    NAMESPACE_SEMANTIC_EVIDENCE,
)


PROTECTED_EFFECT_CHECKER_ID = "protected-effect-integrity"
PROTECTED_EFFECT_CHECKER_VERSION = "0.1.0"
PROTECTED_EFFECT_GUARANTEE = "protected_effect_integrity_v1"
PROTECTED_EFFECT_REUSE_SCHEMA = "ovk.protected_effect_reuse.v1"


class BindingCheckerFingerprint(BaseModel):
    """Observed checker identity for one resource-binding engine."""

    checker_id: str
    checker_version: str
    engine: str
    tool_version: str | None = None

    @field_validator("checker_id", "checker_version", "engine")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("binding checker fingerprint fields must be non-empty")
        return value


class ProtectedEffectExecutionFingerprint(BaseModel):
    """Trusted execution identity required for reusable Protected Effect evidence."""

    environment_digest: str
    tool_digest: str
    worker_image_digest: str
    native_execution: bool
    binding_checkers: list[BindingCheckerFingerprint] = Field(default_factory=list)

    @field_validator("environment_digest", "tool_digest", "worker_image_digest")
    @classmethod
    def _fingerprint_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("execution fingerprint digests must be non-empty")
        return value

    def canonical_payload(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload["binding_checkers"] = sorted(
            payload["binding_checkers"],
            key=lambda item: (
                item["checker_id"],
                item["checker_version"],
                item["engine"],
                item.get("tool_version") or "",
            ),
        )
        return payload

    @property
    def fingerprint_digest(self) -> str:
        return content_digest(self.canonical_payload())


class ProtectedEffectReusePolicy(BaseModel):
    """Strict local policy for reusing prior semantic evidence."""

    max_age_seconds: int = Field(default=86400, gt=0)
    clock_skew_seconds: int = Field(default=300, ge=0)
    require_signature: bool = False
    revoked_evidence_digests: list[str] = Field(default_factory=list)


class ProtectedEffectReuseDecision(BaseModel):
    """Machine-readable eligibility result for one prior evidence record."""

    eligible: bool
    reason_codes: list[str] = Field(default_factory=list)
    evidence_digest: str | None = None
    protected_effect_id: str
    semantic_slice_digest: str
    execution_fingerprint_digest: str


def _observed_binding_checkers(
    evaluation: ProtectedEffectIntegrityEvaluation,
) -> list[BindingCheckerFingerprint]:
    seen: dict[tuple[str, str, str, str | None], BindingCheckerFingerprint] = {}
    for item in evaluation.resource_binding_evidence:
        if not item.checker_id or not item.checker_version or not item.engine:
            continue
        key = (
            item.checker_id,
            item.checker_version,
            item.engine,
            item.tool_version,
        )
        seen[key] = BindingCheckerFingerprint(
            checker_id=item.checker_id,
            checker_version=item.checker_version,
            engine=item.engine,
            tool_version=item.tool_version,
        )
    return sorted(
        seen.values(),
        key=lambda item: (
            item.checker_id,
            item.checker_version,
            item.engine,
            item.tool_version or "",
        ),
    )


def build_execution_fingerprint(
    evaluation: ProtectedEffectIntegrityEvaluation,
    *,
    environment_digest: str,
    tool_digest: str,
    worker_image_digest: str,
    native_execution: bool,
) -> ProtectedEffectExecutionFingerprint:
    """Build a reusable execution fingerprint from observed checker provenance."""

    return ProtectedEffectExecutionFingerprint(
        environment_digest=environment_digest,
        tool_digest=tool_digest,
        worker_image_digest=worker_image_digest,
        native_execution=native_execution,
        binding_checkers=_observed_binding_checkers(evaluation),
    )


def _fingerprint_matches_evaluation(
    fingerprint: ProtectedEffectExecutionFingerprint,
    evaluation: ProtectedEffectIntegrityEvaluation,
) -> bool:
    expected = [
        item.model_dump(mode="json")
        for item in _observed_binding_checkers(evaluation)
    ]
    actual = [
        item.model_dump(mode="json")
        for item in sorted(
            fingerprint.binding_checkers,
            key=lambda item: (
                item.checker_id,
                item.checker_version,
                item.engine,
                item.tool_version or "",
            ),
        )
    ]
    return actual == expected


def _status(status: str) -> VerificationStatus:
    return {
        "pass": VerificationStatus.PASS,
        "fail": VerificationStatus.FAIL,
        "unknown": VerificationStatus.UNKNOWN,
    }.get(status, VerificationStatus.UNKNOWN)


def _counterexamples(evaluation: ProtectedEffectIntegrityEvaluation) -> list[dict[str, Any]]:
    return [
        item.counterexample
        for item in evaluation.resource_binding_evidence
        if item.counterexample is not None
    ]


def _shadow_decision(
    *,
    status: VerificationStatus,
    finding_id: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "decision_state": "needs_review",
        "original_decision_state": "needs_review",
        "merge_recommendation": "require_human_review",
        "human_review_required": True,
        "routing_enforced": False,
        "aggregation_reason": (
            "Protected Effect evidence is shadow/non-controlling: " + reason
        ),
        "controlling_finding_ids": [],
        "finding_contributions": [
            {
                "finding_id": finding_id,
                "claim_status": status.value,
                "required": False,
                "contribution": "non_controlling",
                "detail": "shadow Protected Effect Integrity evidence",
            }
        ],
        "fallback_used": False,
        "fallback_accepted": False,
        "fallback_cause": None,
    }


def _subject(ir: AssuranceIR) -> dict[str, Any]:
    return ir.subject.model_dump(mode="json", exclude_none=True)


def _semantic_artifact(
    *,
    protected_effect_id: str,
    semantic_slice_digest: str,
) -> dict[str, Any]:
    return {
        "kind": "protected_effect_semantic_slice",
        "protected_effect_id": protected_effect_id,
        "semantic_slice_digest": semantic_slice_digest,
    }


def _execution_artifact(
    fingerprint: ProtectedEffectExecutionFingerprint,
) -> dict[str, Any]:
    return {
        "kind": "protected_effect_execution_fingerprint",
        "schema_version": PROTECTED_EFFECT_REUSE_SCHEMA,
        **fingerprint.canonical_payload(),
        "fingerprint_digest": fingerprint.fingerprint_digest,
    }


def protected_effect_evaluation_to_evidence(
    ir: AssuranceIR,
    evaluation: ProtectedEffectIntegrityEvaluation,
    *,
    policy_digest: str,
    execution_fingerprint: ProtectedEffectExecutionFingerprint | None = None,
    signing_key: bytes | None = None,
) -> VerificationEvidence:
    """Project one Protected Effect evaluation into sealed shadow evidence."""

    if evaluation.assurance_ir_digest != ir.assurance_ir_digest:
        raise ValueError("evaluation Assurance IR digest does not match supplied IR")
    if evaluation.protected_effect_id not in {
        effect.protected_effect_id for effect in ir.protected_effects
    }:
        raise ValueError("evaluation protected effect is absent from supplied IR")
    policy_digest = policy_digest.strip()
    if not policy_digest:
        raise ValueError("policy_digest must be non-empty")

    if execution_fingerprint is not None and not _fingerprint_matches_evaluation(
        execution_fingerprint,
        evaluation,
    ):
        raise ValueError(
            "execution fingerprint binding_checkers do not match observed evaluation provenance"
        )

    semantic_digest = protected_effect_semantic_digest(
        ir,
        evaluation.protected_effect_id,
    )
    status = _status(evaluation.status)
    finding_id = f"{evaluation.obligation_id}:{PROTECTED_EFFECT_CHECKER_ID}"

    intent = {
        "intent_id": "protected-effect-integrity",
        "title": "Protected Effect Integrity",
        "risk": {"severity": "high"},
        "provenance": {"inferred": True},
        "protected_effect_id": evaluation.protected_effect_id,
        "semantic_slice_digest": semantic_digest,
    }
    change_origin = {
        "source": "assurance_ir",
        "assurance_ir_digest": ir.assurance_ir_digest,
    }

    generated_artifacts: list[dict[str, Any]] = [
        _semantic_artifact(
            protected_effect_id=evaluation.protected_effect_id,
            semantic_slice_digest=semantic_digest,
        ),
        {
            "kind": "protected_effect_integrity_evaluation",
            "evaluation": evaluation.model_dump(mode="json"),
        },
        {
            "kind": "backend_provenance",
            "backend": PROTECTED_EFFECT_CHECKER_ID,
            "native_execution": (
                execution_fingerprint.native_execution
                if execution_fingerprint is not None
                else False
            ),
            "tool_digest": (
                execution_fingerprint.tool_digest
                if execution_fingerprint is not None
                else None
            ),
        },
    ]
    if execution_fingerprint is not None:
        generated_artifacts.append(_execution_artifact(execution_fingerprint))

    evidence = VerificationEvidence(
        evidence_id=(
            "ev-pei-"
            + content_digest(
                {
                    "obligation_id": evaluation.obligation_id,
                    "assurance_ir_digest": ir.assurance_ir_digest,
                    "semantic_slice_digest": semantic_digest,
                    "status": evaluation.status,
                }
            )[:20]
        ),
        schema_version="ovk.evidence.v1",
        subject=_subject(ir),
        intent=intent,
        backend_claims=[
            BackendClaim(
                backend=PROTECTED_EFFECT_CHECKER_ID,
                guarantee_type=PROTECTED_EFFECT_GUARANTEE,
                status=status,
                assumptions=list(evaluation.assumptions),
                limits=[
                    "Assurance is relative to the supported Assurance IR extraction profile.",
                    "This evidence is shadow and does not control merge decisions.",
                    "Cross-revision reuse additionally requires a complete matching execution fingerprint.",
                ],
                adapter_version=PROTECTED_EFFECT_CHECKER_VERSION,
                required=False,
            )
        ],
        decision=_shadow_decision(
            status=status,
            finding_id=finding_id,
            reason=evaluation.reason,
        ),
        change_origin=change_origin,
        counterexamples=_counterexamples(evaluation),
        generated_artifacts=generated_artifacts,
        obligation_id=evaluation.obligation_id,
        compiler={
            "compiler_id": ir.extractor.extractor_id,
            "compiler_version": ir.extractor.extractor_version,
        },
        coverage=ir.coverage.model_dump(mode="json"),
        aggregation_policy="ovk.protected_effect.shadow.v1",
        routing_enforced=False,
    )

    # Satisfy legacy input-digest artifact expectations without changing the
    # integrity-envelope digest definition. recompute_input_digest ignores
    # generated_artifacts, so adding this artifact is stable.
    input_digest = recompute_input_digest(evidence)
    evidence.generated_artifacts.append(
        {"kind": "input_digest", "digest": input_digest}
    )

    return seal_evidence(
        evidence,
        key=signing_key,
        configuration_digest=content_digest(
            {
                "checker_id": PROTECTED_EFFECT_CHECKER_ID,
                "checker_version": PROTECTED_EFFECT_CHECKER_VERSION,
                "semantic_slice_digest": semantic_digest,
                "execution_fingerprint": (
                    execution_fingerprint.canonical_payload()
                    if execution_fingerprint is not None
                    else None
                ),
            }
        ),
        policy_digest=policy_digest,
        relevant_file_digests=[],
    )


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


def _parse_completed_at(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def evaluate_protected_effect_evidence_reuse(
    evidence: VerificationEvidence,
    *,
    head_ir: AssuranceIR,
    protected_effect_id: str,
    policy_digest: str,
    current_fingerprint: ProtectedEffectExecutionFingerprint,
    reuse_policy: ProtectedEffectReusePolicy | None = None,
    signature_key: bytes | None = None,
    now: datetime | None = None,
) -> ProtectedEffectReuseDecision:
    """Strictly decide whether prior sealed PASS evidence may be reused."""

    policy = reuse_policy or ProtectedEffectReusePolicy()
    current_semantic_digest = protected_effect_semantic_digest(
        head_ir,
        protected_effect_id,
    )
    reasons: list[str] = []

    if not is_supported_schema_version(evidence.schema_version):
        reasons.append("unsupported_schema")
    if not integrity_envelope_complete(evidence):
        reasons.append("incomplete_integrity_envelope")
    if not verify_evidence_digest(evidence):
        reasons.append("invalid_evidence_digest")
    if evidence.signature is not None:
        if not verify_evidence_signature(evidence, key=signature_key):
            reasons.append("invalid_signature")
    elif policy.require_signature:
        reasons.append("signature_required")

    evidence_digest = evidence.evidence_digest
    if (
        evidence_digest is not None
        and evidence_digest in set(policy.revoked_evidence_digests)
    ):
        reasons.append("evidence_revoked")

    completed = _parse_completed_at(evidence.completed_at)
    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if completed is None:
        reasons.append("invalid_completed_at")
    else:
        age = (current_time - completed).total_seconds()
        if age < -policy.clock_skew_seconds:
            reasons.append("evidence_from_future")
        elif age > policy.max_age_seconds:
            reasons.append("evidence_expired")

    subject_repo = str(evidence.subject.get("repo") or "")
    if subject_repo != head_ir.subject.repo:
        reasons.append("repository_mismatch")

    semantic = _single_artifact(evidence, "protected_effect_semantic_slice")
    if semantic is None:
        reasons.append("missing_or_ambiguous_semantic_slice")
    else:
        if semantic.get("protected_effect_id") != protected_effect_id:
            reasons.append("protected_effect_mismatch")
        if semantic.get("semantic_slice_digest") != current_semantic_digest:
            reasons.append("semantic_slice_mismatch")

    if evidence.policy_digest != policy_digest:
        reasons.append("policy_digest_mismatch")
    if evidence.checker_id != PROTECTED_EFFECT_CHECKER_ID:
        reasons.append("checker_id_mismatch")
    if evidence.checker_version != PROTECTED_EFFECT_CHECKER_VERSION:
        reasons.append("checker_version_mismatch")

    claims = [
        claim
        for claim in evidence.backend_claims
        if claim.backend == PROTECTED_EFFECT_CHECKER_ID
        and claim.guarantee_type == PROTECTED_EFFECT_GUARANTEE
    ]
    if len(claims) != 1:
        reasons.append("missing_or_ambiguous_protected_effect_claim")
    else:
        claim = claims[0]
        if claim.status != VerificationStatus.PASS:
            reasons.append("prior_claim_not_pass")
        if claim.required:
            reasons.append("prior_claim_not_shadow")

    decision_state = str(evidence.decision.get("decision_state") or "")
    controlling_ids = list(evidence.decision.get("controlling_finding_ids") or [])
    if decision_state != "needs_review" or controlling_ids:
        reasons.append("prior_evidence_not_non_controlling")

    fingerprint_artifact = _single_artifact(
        evidence,
        "protected_effect_execution_fingerprint",
    )
    if fingerprint_artifact is None:
        reasons.append("missing_or_ambiguous_execution_fingerprint")
    else:
        try:
            stored_fingerprint = ProtectedEffectExecutionFingerprint.model_validate(
                {
                    "environment_digest": fingerprint_artifact.get("environment_digest"),
                    "tool_digest": fingerprint_artifact.get("tool_digest"),
                    "worker_image_digest": fingerprint_artifact.get("worker_image_digest"),
                    "native_execution": fingerprint_artifact.get("native_execution"),
                    "binding_checkers": fingerprint_artifact.get("binding_checkers") or [],
                }
            )
        except Exception:
            reasons.append("invalid_execution_fingerprint")
        else:
            if stored_fingerprint != current_fingerprint:
                reasons.append("execution_fingerprint_mismatch")
            if (
                fingerprint_artifact.get("fingerprint_digest")
                != stored_fingerprint.fingerprint_digest
            ):
                reasons.append("execution_fingerprint_digest_mismatch")

    return ProtectedEffectReuseDecision(
        eligible=not reasons,
        reason_codes=sorted(set(reasons)),
        evidence_digest=evidence_digest,
        protected_effect_id=protected_effect_id,
        semantic_slice_digest=current_semantic_digest,
        execution_fingerprint_digest=current_fingerprint.fingerprint_digest,
    )


def build_protected_effect_cache_components(
    *,
    ir: AssuranceIR,
    protected_effect_id: str,
    policy_digest: str,
    execution_fingerprint: ProtectedEffectExecutionFingerprint,
) -> dict[str, Any]:
    """Cross-revision cache identity for one semantically stable protected effect."""

    return {
        "cache_schema_version": "ovk.semantic_evidence_cache.v1",
        "ovk_version": OVK_VERSION,
        # Deliberately bind repository but not head SHA. Semantic slice identity
        # is the cross-revision content address.
        "subject": {"repo": ir.subject.repo},
        "protected_effect_id": protected_effect_id,
        "semantic_slice_digest": protected_effect_semantic_digest(
            ir,
            protected_effect_id,
        ),
        "policy_digest": policy_digest,
        "checker_id": PROTECTED_EFFECT_CHECKER_ID,
        "checker_version": PROTECTED_EFFECT_CHECKER_VERSION,
        "guarantee_type": PROTECTED_EFFECT_GUARANTEE,
        "environment_digest": execution_fingerprint.environment_digest,
        "tool_digest": execution_fingerprint.tool_digest,
        "worker_image_digest": execution_fingerprint.worker_image_digest,
        "execution_fingerprint_digest": execution_fingerprint.fingerprint_digest,
        "namespace": NAMESPACE_SEMANTIC_EVIDENCE,
    }


def reissue_reused_protected_effect_evidence(
    prior: VerificationEvidence,
    *,
    head_ir: AssuranceIR,
    protected_effect_id: str,
    policy_digest: str,
    current_fingerprint: ProtectedEffectExecutionFingerprint,
    reuse_decision: ProtectedEffectReuseDecision,
    signing_key: bytes | None = None,
) -> VerificationEvidence:
    """Issue a new sealed head record that references eligible prior PASS evidence."""

    if not reuse_decision.eligible:
        raise ValueError("cannot reissue ineligible Protected Effect evidence")
    if prior.evidence_digest != reuse_decision.evidence_digest:
        raise ValueError("reuse decision is not bound to supplied prior evidence")

    semantic_digest = protected_effect_semantic_digest(head_ir, protected_effect_id)
    claim = next(
        claim
        for claim in prior.backend_claims
        if claim.backend == PROTECTED_EFFECT_CHECKER_ID
        and claim.guarantee_type == PROTECTED_EFFECT_GUARANTEE
    )
    finding_id = f"reuse:{protected_effect_id}:{prior.evidence_digest}"

    intent = {
        "intent_id": "protected-effect-integrity",
        "title": "Protected Effect Integrity",
        "risk": {"severity": "high"},
        "provenance": {"inferred": True},
        "protected_effect_id": protected_effect_id,
        "semantic_slice_digest": semantic_digest,
    }
    change_origin = {
        "source": "reused_sealed_evidence",
        "prior_evidence_digest": prior.evidence_digest,
        "head_assurance_ir_digest": head_ir.assurance_ir_digest,
    }

    evidence = VerificationEvidence(
        evidence_id=(
            "ev-pei-reuse-"
            + content_digest(
                {
                    "prior_evidence_digest": prior.evidence_digest,
                    "head_assurance_ir_digest": head_ir.assurance_ir_digest,
                    "protected_effect_id": protected_effect_id,
                }
            )[:20]
        ),
        schema_version="ovk.evidence.v1",
        subject=_subject(head_ir),
        intent=intent,
        backend_claims=[
            claim.model_copy(
                update={
                    "required": False,
                    "assumptions": [
                        *claim.assumptions,
                        "Current semantic slice and strict execution provenance matched prior sealed evidence.",
                    ],
                }
            )
        ],
        decision=_shadow_decision(
            status=VerificationStatus.PASS,
            finding_id=finding_id,
            reason="strictly validated reuse of prior sealed PASS evidence",
        ),
        change_origin=change_origin,
        generated_artifacts=[
            _semantic_artifact(
                protected_effect_id=protected_effect_id,
                semantic_slice_digest=semantic_digest,
            ),
            _execution_artifact(current_fingerprint),
            {
                "kind": "protected_effect_evidence_reuse",
                "prior_evidence_digest": prior.evidence_digest,
                "reuse_decision": reuse_decision.model_dump(mode="json"),
            },
            {
                "kind": "backend_provenance",
                "backend": PROTECTED_EFFECT_CHECKER_ID,
                "native_execution": current_fingerprint.native_execution,
                "tool_digest": current_fingerprint.tool_digest,
                "reused": True,
            },
        ],
        compiler={
            "compiler_id": head_ir.extractor.extractor_id,
            "compiler_version": head_ir.extractor.extractor_version,
        },
        coverage=head_ir.coverage.model_dump(mode="json"),
        aggregation_policy="ovk.protected_effect.shadow.v1",
        routing_enforced=False,
    )
    evidence.generated_artifacts.append(
        {"kind": "input_digest", "digest": recompute_input_digest(evidence)}
    )
    return seal_evidence(
        evidence,
        key=signing_key,
        configuration_digest=content_digest(
            {
                "checker_id": PROTECTED_EFFECT_CHECKER_ID,
                "checker_version": PROTECTED_EFFECT_CHECKER_VERSION,
                "semantic_slice_digest": semantic_digest,
                "execution_fingerprint": current_fingerprint.canonical_payload(),
                "reused_from": prior.evidence_digest,
            }
        ),
        policy_digest=policy_digest,
        relevant_file_digests=[],
    )


class ProtectedEffectEvidenceCache:
    """Hardened semantic-evidence cache with strict cross-revision validation."""

    def __init__(self, cache: HardenedResultCache | None = None) -> None:
        self.cache = cache or HardenedResultCache()

    def put(
        self,
        *,
        ir: AssuranceIR,
        protected_effect_id: str,
        policy_digest: str,
        execution_fingerprint: ProtectedEffectExecutionFingerprint,
        evidence: VerificationEvidence,
    ) -> str:
        decision = evaluate_protected_effect_evidence_reuse(
            evidence,
            head_ir=ir,
            protected_effect_id=protected_effect_id,
            policy_digest=policy_digest,
            current_fingerprint=execution_fingerprint,
        )
        if not decision.eligible:
            raise ValueError(
                "Protected Effect evidence is not cache-reusable: "
                + ", ".join(decision.reason_codes)
            )
        components = build_protected_effect_cache_components(
            ir=ir,
            protected_effect_id=protected_effect_id,
            policy_digest=policy_digest,
            execution_fingerprint=execution_fingerprint,
        )
        return self.cache.put(
            components,
            evidence.model_dump(mode="json"),
            meta={
                "evidence_digest": evidence.evidence_digest,
                "semantic_reuse": True,
            },
        )

    def reuse_for_head(
        self,
        *,
        head_ir: AssuranceIR,
        protected_effect_id: str,
        policy_digest: str,
        current_fingerprint: ProtectedEffectExecutionFingerprint,
        reuse_policy: ProtectedEffectReusePolicy | None = None,
        signature_key: bytes | None = None,
        signing_key: bytes | None = None,
        now: datetime | None = None,
    ) -> VerificationEvidence | None:
        components = build_protected_effect_cache_components(
            ir=head_ir,
            protected_effect_id=protected_effect_id,
            policy_digest=policy_digest,
            execution_fingerprint=current_fingerprint,
        )
        entry = self.cache.get(components)
        if entry is None:
            return None
        try:
            prior = VerificationEvidence.model_validate(entry.payload)
        except Exception:
            return None

        decision = evaluate_protected_effect_evidence_reuse(
            prior,
            head_ir=head_ir,
            protected_effect_id=protected_effect_id,
            policy_digest=policy_digest,
            current_fingerprint=current_fingerprint,
            reuse_policy=reuse_policy,
            signature_key=signature_key,
            now=now,
        )
        if not decision.eligible:
            return None
        return reissue_reused_protected_effect_evidence(
            prior,
            head_ir=head_ir,
            protected_effect_id=protected_effect_id,
            policy_digest=policy_digest,
            current_fingerprint=current_fingerprint,
            reuse_decision=decision,
            signing_key=signing_key,
        )
