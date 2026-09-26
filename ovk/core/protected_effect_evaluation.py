"""Compose Protected Effect Integrity obligations with backend evidence.

This module is the first end-to-end semantic evaluator over Assurance IR. It
preserves three-valued outcomes:

- pass: complete extraction coverage and every required integrity dimension is
  established;
- fail: at least one integrity dimension has a concrete violation;
- unknown: no violation is established, but extraction or proof evidence is
  incomplete.

It does not emit an OVK merge recommendation.
"""

from __future__ import annotations

from typing import Any, Callable, Literal

from pydantic import BaseModel, Field

from ovk.adapters.z3.resource_binding import evaluate_resource_binding_with_z3
from ovk.core.assurance_ir import AssuranceIR, ResourceBinding
from ovk.core.protected_effect_integrity import (
    IntegrityCheck,
    ProtectedEffectIntegrityObligation,
    compile_protected_effect_integrity,
)


EvaluationStatus = Literal["pass", "fail", "unknown"]
BindingEvaluator = Callable[[AssuranceIR, ResourceBinding], dict[str, Any]]


class ResourceBindingEvidence(BaseModel):
    binding_id: str
    status: EvaluationStatus
    reason: str
    counterexample: dict[str, Any] | None = None


class ProtectedEffectIntegrityEvaluation(BaseModel):
    schema_version: Literal["ovk.protected_effect_integrity.evaluation.v1"] = (
        "ovk.protected_effect_integrity.evaluation.v1"
    )
    obligation_id: str
    protected_effect_id: str
    assurance_ir_digest: str
    extraction_coverage: str
    status: EvaluationStatus
    reason: str
    checks: list[IntegrityCheck]
    resource_binding_evidence: list[ResourceBindingEvidence] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


def _binding_map(ir: AssuranceIR) -> dict[str, ResourceBinding]:
    return {binding.binding_id: binding for binding in ir.resource_bindings}


def _resolve_resource_check(
    *,
    ir: AssuranceIR,
    obligation: ProtectedEffectIntegrityObligation,
    check: IntegrityCheck,
    evaluator: BindingEvaluator,
) -> tuple[IntegrityCheck, list[ResourceBindingEvidence]]:
    if check.dimension != "resource_binding" or check.status != "unknown":
        return check, []

    bindings = _binding_map(ir)
    evidence: list[ResourceBindingEvidence] = []
    for binding_id in obligation.resource_binding_ids:
        binding = bindings.get(binding_id)
        if binding is None:
            evidence.append(
                ResourceBindingEvidence(
                    binding_id=binding_id,
                    status="unknown",
                    reason="resource-binding obligation is absent from Assurance IR",
                )
            )
            continue
        raw = evaluator(ir, binding)
        status = str(raw.get("status", "unknown"))
        if status not in {"pass", "fail", "unknown"}:
            status = "unknown"
        evidence.append(
            ResourceBindingEvidence(
                binding_id=binding_id,
                status=status,
                reason=str(raw.get("reason", "resource-binding evaluator returned no reason")),
                counterexample=raw.get("counterexample"),
            )
        )

    if not evidence:
        return check, evidence

    # Candidate authorization guards are alternatives. A single established
    # binding is sufficient. A violation is conclusive only when every candidate
    # binding is refuted. Otherwise uncertainty is preserved.
    if any(item.status == "pass" for item in evidence):
        return (
            IntegrityCheck(
                dimension="resource_binding",
                status="established",
                reason="at least one candidate authorization guard has an established resource binding",
                evidence_ids=sorted(item.binding_id for item in evidence if item.status == "pass"),
            ),
            evidence,
        )

    if evidence and all(item.status == "fail" for item in evidence):
        return (
            IntegrityCheck(
                dimension="resource_binding",
                status="violated",
                reason="every candidate authorization guard has a refuted resource binding",
                evidence_ids=sorted(item.binding_id for item in evidence),
            ),
            evidence,
        )

    return (
        IntegrityCheck(
            dimension="resource_binding",
            status="unknown",
            reason="no candidate resource binding is established and at least one remains unresolved",
            evidence_ids=sorted(item.binding_id for item in evidence),
        ),
        evidence,
    )


def _overall_status(
    *,
    checks: list[IntegrityCheck],
    extraction_coverage: str,
) -> tuple[EvaluationStatus, str]:
    violated = [check.dimension for check in checks if check.status == "violated"]
    if violated:
        return "fail", "integrity violation established in: " + ", ".join(sorted(violated))

    if extraction_coverage != "complete":
        return (
            "unknown",
            f"source extraction coverage is {extraction_coverage}; pass claims require complete coverage",
        )

    unresolved = [check.dimension for check in checks if check.status == "unknown"]
    if unresolved:
        return "unknown", "integrity obligations unresolved in: " + ", ".join(sorted(unresolved))

    return "pass", "all protected-effect integrity dimensions are established under declared assumptions"


def evaluate_protected_effect_integrity(
    ir: AssuranceIR,
    *,
    resource_binding_evaluator: BindingEvaluator = evaluate_resource_binding_with_z3,
) -> list[ProtectedEffectIntegrityEvaluation]:
    """Evaluate all protected effects represented by an Assurance IR."""

    results: list[ProtectedEffectIntegrityEvaluation] = []
    for obligation in compile_protected_effect_integrity(ir):
        checks: list[IntegrityCheck] = []
        resource_evidence: list[ResourceBindingEvidence] = []

        for check in obligation.checks:
            resolved, evidence = _resolve_resource_check(
                ir=ir,
                obligation=obligation,
                check=check,
                evaluator=resource_binding_evaluator,
            )
            checks.append(resolved)
            resource_evidence.extend(evidence)

        status, reason = _overall_status(
            checks=checks,
            extraction_coverage=ir.coverage.status,
        )
        results.append(
            ProtectedEffectIntegrityEvaluation(
                obligation_id=obligation.obligation_id,
                protected_effect_id=obligation.protected_effect_id,
                assurance_ir_digest=ir.assurance_ir_digest,
                extraction_coverage=ir.coverage.status,
                status=status,
                reason=reason,
                checks=checks,
                resource_binding_evidence=resource_evidence,
                assumptions=[
                    *obligation.assumptions,
                    *ir.coverage.assumptions,
                ],
            )
        )

    return results
