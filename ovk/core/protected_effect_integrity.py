"""Protected-effect integrity obligation construction.

This module defines the first assurance theorem family over Assurance IR:

    Performed(principal, effect, resource)
        -> Authorized(principal, effect, resource)

The compiler is deliberately conservative. It does not prove resource identity or
source-level dominance. It decomposes one protected effect into explicit
sub-obligations and records which parts are structurally established, violated,
or still require a stronger backend.

No merge decision is produced here.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ovk.core.assurance_ir import AssuranceIR, AuthorizationGuard, ProtectedEffect, ResourceBinding, SemanticPath


DimensionStatus = Literal["established", "violated", "unknown"]
IntegrityDimension = Literal[
    "guard_presence",
    "guard_effectiveness",
    "principal_binding",
    "effect_binding",
    "resource_binding",
    "path_binding",
]


class IntegrityCheck(BaseModel):
    dimension: IntegrityDimension
    status: DimensionStatus
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)


class ProtectedEffectIntegrityObligation(BaseModel):
    schema_version: Literal["ovk.protected_effect_integrity.v1"] = "ovk.protected_effect_integrity.v1"
    obligation_id: str
    claim_id: str | None = None
    protected_effect_id: str
    path_ids: list[str] = Field(default_factory=list)
    candidate_guard_ids: list[str] = Field(default_factory=list)
    resource_binding_ids: list[str] = Field(default_factory=list)
    checks: list[IntegrityCheck] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)

    @property
    def structural_status(self) -> DimensionStatus:
        statuses = {check.status for check in self.checks}
        if "violated" in statuses:
            return "violated"
        if "unknown" in statuses:
            return "unknown"
        return "established"


def _paths_for_effect(ir: AssuranceIR, effect: ProtectedEffect) -> list[SemanticPath]:
    return [path for path in ir.paths if effect.protected_effect_id in path.protected_effect_ids]


def _guards_for_paths(ir: AssuranceIR, paths: list[SemanticPath]) -> list[AuthorizationGuard]:
    guard_ids = {guard_id for path in paths for guard_id in path.guard_ids}
    return [guard for guard in ir.guards if guard.guard_id in guard_ids]


def _bindings_for_pair(
    ir: AssuranceIR,
    guard: AuthorizationGuard,
    effect: ProtectedEffect,
) -> list[ResourceBinding]:
    return [
        binding
        for binding in ir.resource_bindings
        if binding.authorized_resource_id == guard.resource_id
        and binding.acted_resource_id == effect.resource_id
    ]


def _matching_claim_id(ir: AssuranceIR, effect: ProtectedEffect) -> str | None:
    candidates = [
        claim.claim_id
        for claim in ir.claims
        if claim.claim_kind == "protected_effect_integrity"
        and effect.protected_effect_id in claim.subject_ids
    ]
    return sorted(candidates)[0] if candidates else None


def compile_protected_effect_integrity(ir: AssuranceIR) -> list[ProtectedEffectIntegrityObligation]:
    """Compile one conservative structural obligation per protected effect.

    Structural checks are intentionally weaker than source-level proof:

    - a guard must lie on a semantic path that also contains the protected effect;
    - principal and effect references must agree;
    - resource identity is established structurally only when the guard and
      protected effect reference the same ResourceRef;
    - an explicit ResourceBinding between distinct resources records the proof
      obligation but remains unknown until a backend establishes its predicate.

    This compiler never treats an asserted ResourceBinding as proof of equality.
    """

    obligations: list[ProtectedEffectIntegrityObligation] = []

    for effect in sorted(ir.protected_effects, key=lambda item: item.protected_effect_id):
        paths = _paths_for_effect(ir, effect)
        guards = _guards_for_paths(ir, paths)

        checks: list[IntegrityCheck] = []
        binding_ids: set[str] = set()

        if not paths:
            checks.append(
                IntegrityCheck(
                    dimension="path_binding",
                    status="unknown",
                    reason="protected effect is not attached to a semantic path",
                )
            )
        else:
            checks.append(
                IntegrityCheck(
                    dimension="path_binding",
                    status="established",
                    reason="protected effect is attached to at least one semantic path",
                    evidence_ids=sorted(path.path_id for path in paths),
                )
            )

        if not guards:
            checks.append(
                IntegrityCheck(
                    dimension="guard_presence",
                    status="violated" if paths else "unknown",
                    reason=(
                        "no authorization guard is present on a path containing the protected effect"
                        if paths
                        else "guard presence cannot be assessed without a semantic path"
                    ),
                )
            )
        else:
            checks.append(
                IntegrityCheck(
                    dimension="guard_presence",
                    status="established",
                    reason="at least one authorization guard is present on a protected-effect path",
                    evidence_ids=sorted(guard.guard_id for guard in guards),
                )
            )

        principal_matches = [guard for guard in guards if guard.principal_id == effect.principal_id]
        if not guards:
            principal_status: DimensionStatus = "unknown"
            principal_reason = "principal binding cannot be assessed without a candidate guard"
        elif not principal_matches:
            principal_status = "violated"
            principal_reason = "no candidate guard authorizes the principal that performs the effect"
        else:
            principal_status = "established"
            principal_reason = "at least one candidate guard binds the protected-effect principal"
        checks.append(
            IntegrityCheck(
                dimension="principal_binding",
                status=principal_status,
                reason=principal_reason,
                evidence_ids=sorted(guard.guard_id for guard in principal_matches),
            )
        )

        effect_matches = [guard for guard in principal_matches if guard.effect_id == effect.effect_id]
        if not principal_matches:
            effect_status: DimensionStatus = "unknown" if not guards else "violated"
            effect_reason = "effect binding cannot be established without a principal-compatible guard"
        elif not effect_matches:
            effect_status = "violated"
            effect_reason = "no principal-compatible guard authorizes the performed effect"
        else:
            effect_status = "established"
            effect_reason = "at least one guard binds both principal and effect"
        checks.append(
            IntegrityCheck(
                dimension="effect_binding",
                status=effect_status,
                reason=effect_reason,
                evidence_ids=sorted(guard.guard_id for guard in effect_matches),
            )
        )

        effective_guards = [
            guard
            for guard in effect_matches
            if guard.effectiveness == "established"
        ]
        unproved_guards = [
            guard
            for guard in effect_matches
            if guard.effectiveness == "unproved"
        ]
        if effective_guards:
            effectiveness_status: DimensionStatus = "established"
            effectiveness_reason = (
                "at least one principal/effect-compatible guard has proved "
                "authorization effectiveness"
            )
            effectiveness_evidence = sorted(
                {
                    evidence_id
                    for guard in effective_guards
                    for evidence_id in (
                        guard.effectiveness_evidence_ids or [guard.guard_id]
                    )
                }
            )
        elif unproved_guards:
            effectiveness_status = "unknown"
            effectiveness_reason = (
                "candidate authorization guard is source-grounded but its "
                "authorization effectiveness is unproved"
            )
            effectiveness_evidence = sorted(
                guard.guard_id for guard in unproved_guards
            )
        else:
            effectiveness_status = "unknown"
            effectiveness_reason = (
                "guard effectiveness cannot be established without a "
                "principal/effect-compatible candidate guard"
            )
            effectiveness_evidence = []
        checks.append(
            IntegrityCheck(
                dimension="guard_effectiveness",
                status=effectiveness_status,
                reason=effectiveness_reason,
                evidence_ids=effectiveness_evidence,
            )
        )

        exact_resource_guards = [guard for guard in effect_matches if guard.resource_id == effect.resource_id]
        explicit_bindings: list[ResourceBinding] = []
        for guard in effect_matches:
            explicit_bindings.extend(_bindings_for_pair(ir, guard, effect))
        for binding in explicit_bindings:
            binding_ids.add(binding.binding_id)

        if exact_resource_guards:
            resource_status: DimensionStatus = "established"
            resource_reason = "authorization guard and protected effect reference the same resource"
            resource_evidence = sorted(guard.guard_id for guard in exact_resource_guards)
        elif explicit_bindings:
            resource_status = "unknown"
            resource_reason = (
                "an explicit resource-binding obligation exists, but the binding predicate "
                "has not been established by a verifier"
            )
            resource_evidence = sorted(binding.binding_id for binding in explicit_bindings)
        elif effect_matches:
            resource_status = "violated"
            resource_reason = "authorized resource and acted-upon resource differ with no binding obligation"
            resource_evidence = sorted(guard.guard_id for guard in effect_matches)
        else:
            resource_status = "unknown"
            resource_reason = "resource binding cannot be assessed without a principal/effect-compatible guard"
            resource_evidence = []

        checks.append(
            IntegrityCheck(
                dimension="resource_binding",
                status=resource_status,
                reason=resource_reason,
                evidence_ids=resource_evidence,
            )
        )

        obligations.append(
            ProtectedEffectIntegrityObligation(
                obligation_id=f"pei:{effect.protected_effect_id}",
                claim_id=_matching_claim_id(ir, effect),
                protected_effect_id=effect.protected_effect_id,
                path_ids=sorted(path.path_id for path in paths),
                candidate_guard_ids=sorted(guard.guard_id for guard in guards),
                resource_binding_ids=sorted(binding_ids),
                checks=checks,
                assumptions=[
                    "Assurance IR faithfully represents the supported source semantics.",
                    "Semantic-path guard membership conservatively represents control-flow dominance only after extractor validation.",
                ],
            )
        )

    return obligations
