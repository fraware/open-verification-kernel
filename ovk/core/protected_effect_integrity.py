"""Protected-effect integrity obligation construction.

This module defines the first assurance theorem family over Assurance IR:

    Performed(principal, effect, resource)
        -> Authorized(principal, effect, resource)

The compiler is deliberately conservative. It does not prove resource identity.
It proves only a bounded source-level dominance relation over exact conjunctive
condition atoms already present in Assurance IR, then decomposes one protected
effect into explicit sub-obligations and records which parts are structurally
established, violated, or still require a stronger backend.

No merge decision is produced here.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ovk.core.assurance_ir import (
    AssuranceIR,
    AuthorizationGuard,
    GuardDominanceEvidence,
    ProtectedEffect,
    ResourceBinding,
    SemanticPath,
)



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
    path_candidate_guard_ids: dict[str, list[str]] = Field(default_factory=dict)
    path_exact_resource_guard_ids: dict[str, list[str]] = Field(default_factory=dict)
    path_resource_binding_ids: dict[str, list[str]] = Field(default_factory=dict)
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


def _known_condition_ids(ir: AssuranceIR) -> set[str]:
    return {condition.condition_id for condition in ir.conditions}


def _path_is_complete(ir: AssuranceIR, path: SemanticPath) -> bool:
    if path.coverage_status is None:
        return ir.coverage.status == "complete"
    return path.coverage_status == "complete"


def _conditions_imply(
    *,
    ir: AssuranceIR,
    required_ids: list[str],
    available_ids: set[str],
) -> bool:
    """Prove implication in the bounded conjunctive condition calculus.

    Conditions are source-grounded atoms. A required condition is established
    only when the exact known atom is present on the effect path. This is
    deliberately syntactic: no Boolean algebra or solver equivalence is
    inferred here.
    """

    required = set(required_ids)
    if not required:
        return True
    known = _known_condition_ids(ir)
    return required <= known and required <= available_ids


def _dominance_evidence_for(
    ir: AssuranceIR,
    guard: AuthorizationGuard,
    effect: ProtectedEffect,
) -> GuardDominanceEvidence | None:
    matches = [
        item
        for item in ir.guard_dominance_evidence
        if item.guard_id == guard.guard_id
        and item.protected_effect_id == effect.protected_effect_id
    ]
    if not matches:
        return None
    return sorted(matches, key=lambda item: item.evidence_id)[0]


def _guard_dominance_status_on_path(
    *,
    ir: AssuranceIR,
    guard: AuthorizationGuard,
    effect: ProtectedEffect,
    path: SemanticPath,
) -> DimensionStatus:
    """Resolve structural guard dominance independently of effectiveness.

    Presence of CFG evidence means the guard is body-executed and CFG binding
    is authoritative. Ambiguous binding or partial sink coverage is UNKNOWN;
    it must never fall back to the legacy condition calculus. Guards with no
    CFG evidence retain entrypoint/condition semantics for compatibility with
    dependency and decorator authorization.
    """

    cfg_evidence = _dominance_evidence_for(ir, guard, effect)
    if cfg_evidence is not None:
        if cfg_evidence.coverage_status != "complete":
            return "unknown"
        if (
            cfg_evidence.guard_cfg_node_id is None
            or cfg_evidence.effect_cfg_node_id is None
        ):
            return "unknown"
        return "established" if cfg_evidence.dominates else "violated"

    available = set(effect.condition_ids) | set(path.condition_ids)
    if _conditions_imply(
        ir=ir,
        required_ids=guard.condition_ids,
        available_ids=available,
    ):
        return "established"
    return _path_missing_status(ir, path)


def _binding_applies_on_path(
    *,
    ir: AssuranceIR,
    binding: ResourceBinding,
    effect: ProtectedEffect,
    path: SemanticPath,
) -> bool:
    available = set(effect.condition_ids) | set(path.condition_ids)
    return _conditions_imply(
        ir=ir,
        required_ids=binding.condition_ids,
        available_ids=available,
    )


def _aggregate_path_status(
    statuses: list[DimensionStatus],
) -> DimensionStatus:
    if not statuses:
        return "unknown"
    if "violated" in statuses:
        return "violated"
    if "unknown" in statuses:
        return "unknown"
    return "established"


def _path_missing_status(
    ir: AssuranceIR,
    path: SemanticPath,
) -> DimensionStatus:
    return "violated" if _path_is_complete(ir, path) else "unknown"


def compile_protected_effect_integrity(ir: AssuranceIR) -> list[ProtectedEffectIntegrityObligation]:
    """Compile one path-universal obligation per protected effect.

    Protected Effect Integrity is universal over execution paths. Within each
    represented path, any one qualifying authorization guard is sufficient.
    Across paths, every path that reaches the effect must have a qualifying
    guard.

    Conditional dominance uses a bounded conjunctive calculus: a guard whose
    condition atoms are a subset of the effect/path condition atoms dominates
    that effect on the path. Unconditional guards dominate every path. Unknown
    or logically equivalent-but-differently-rendered conditions are not
    equated.
    """

    obligations: list[ProtectedEffectIntegrityObligation] = []

    guards_by_id = {guard.guard_id: guard for guard in ir.guards}

    for effect in sorted(
        ir.protected_effects,
        key=lambda item: item.protected_effect_id,
    ):
        paths = _paths_for_effect(ir, effect)
        checks: list[IntegrityCheck] = []

        path_candidate_guard_ids: dict[str, list[str]] = {}
        path_exact_resource_guard_ids: dict[str, list[str]] = {}
        path_resource_binding_ids: dict[str, list[str]] = {}

        presence_statuses: list[DimensionStatus] = []
        principal_statuses: list[DimensionStatus] = []
        effect_statuses: list[DimensionStatus] = []
        effectiveness_statuses: list[DimensionStatus] = []
        resource_statuses: list[DimensionStatus] = []

        all_dominating_guards: dict[str, AuthorizationGuard] = {}
        all_principal_guards: dict[str, AuthorizationGuard] = {}
        all_effect_guards: dict[str, AuthorizationGuard] = {}
        all_effective_guards: dict[str, AuthorizationGuard] = {}
        all_binding_ids: set[str] = set()

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

        for path in paths:
            referenced_guards = [
                guards_by_id[guard_id]
                for guard_id in path.guard_ids
                if guard_id in guards_by_id
            ]
            dominance_statuses = {
                guard.guard_id: _guard_dominance_status_on_path(
                    ir=ir,
                    guard=guard,
                    effect=effect,
                    path=path,
                )
                for guard in referenced_guards
            }
            dominating_guards = [
                guard
                for guard in referenced_guards
                if dominance_statuses[guard.guard_id] == "established"
            ]
            path_candidate_guard_ids[path.path_id] = sorted(
                guard.guard_id for guard in dominating_guards
            )
            for guard in dominating_guards:
                all_dominating_guards[guard.guard_id] = guard

            if dominating_guards:
                presence_statuses.append("established")
            elif any(
                status == "unknown"
                for status in dominance_statuses.values()
            ):
                presence_statuses.append("unknown")
            elif not referenced_guards:
                # Absence is a violation only under complete local extraction.
                # Partial coverage cannot prove that no relevant guard exists.
                presence_statuses.append(_path_missing_status(ir, path))
            else:
                # Every represented candidate is structurally refuted.
                presence_statuses.append("violated")

            principal_matches = [
                guard
                for guard in dominating_guards
                if guard.principal_id == effect.principal_id
            ]
            for guard in principal_matches:
                all_principal_guards[guard.guard_id] = guard
            if principal_matches:
                principal_statuses.append("established")
            elif dominating_guards:
                principal_statuses.append("violated")
            else:
                principal_statuses.append("unknown")

            effect_matches = [
                guard
                for guard in principal_matches
                if guard.effect_id == effect.effect_id
            ]
            for guard in effect_matches:
                all_effect_guards[guard.guard_id] = guard
            if effect_matches:
                effect_statuses.append("established")
            elif principal_matches:
                effect_statuses.append("violated")
            else:
                effect_statuses.append("unknown")

            effective_guards = [
                guard
                for guard in effect_matches
                if guard.effectiveness == "established"
            ]
            for guard in effective_guards:
                all_effective_guards[guard.guard_id] = guard
            if effective_guards:
                effectiveness_statuses.append("established")
            elif effect_matches:
                effectiveness_statuses.append("unknown")
            else:
                effectiveness_statuses.append("unknown")

            exact_resource_guards = [
                guard
                for guard in effect_matches
                if guard.resource_id == effect.resource_id
            ]
            path_exact_resource_guard_ids[path.path_id] = sorted(
                guard.guard_id for guard in exact_resource_guards
            )

            explicit_bindings: list[ResourceBinding] = []
            for guard in effect_matches:
                explicit_bindings.extend(
                    binding
                    for binding in _bindings_for_pair(ir, guard, effect)
                    if _binding_applies_on_path(
                        ir=ir,
                        binding=binding,
                        effect=effect,
                        path=path,
                    )
                )
            unique_bindings = {
                binding.binding_id: binding
                for binding in explicit_bindings
            }
            path_resource_binding_ids[path.path_id] = sorted(unique_bindings)
            all_binding_ids.update(unique_bindings)

            if exact_resource_guards:
                resource_statuses.append("established")
            elif unique_bindings:
                resource_statuses.append("unknown")
            elif effect_matches:
                resource_statuses.append("violated")
            else:
                resource_statuses.append("unknown")

        guard_presence_status = _aggregate_path_status(presence_statuses)
        checks.append(
            IntegrityCheck(
                dimension="guard_presence",
                status=guard_presence_status,
                reason=(
                    "every protected-effect path has at least one condition-dominating authorization guard"
                    if guard_presence_status == "established"
                    else (
                        "at least one complete protected-effect path has no condition-dominating authorization guard"
                        if guard_presence_status == "violated"
                        else "guard presence or dominance is unresolved on at least one protected-effect path"
                    )
                ),
                evidence_ids=sorted(all_dominating_guards),
            )
        )

        principal_status = _aggregate_path_status(principal_statuses)
        checks.append(
            IntegrityCheck(
                dimension="principal_binding",
                status=principal_status,
                reason=(
                    "every protected-effect path has a dominating guard for the performing principal"
                    if principal_status == "established"
                    else (
                        "at least one complete path has dominating guards but none for the performing principal"
                        if principal_status == "violated"
                        else "principal binding is unresolved on at least one protected-effect path"
                    )
                ),
                evidence_ids=sorted(all_principal_guards),
            )
        )

        effect_status = _aggregate_path_status(effect_statuses)
        checks.append(
            IntegrityCheck(
                dimension="effect_binding",
                status=effect_status,
                reason=(
                    "every protected-effect path has a principal-compatible guard for the performed effect"
                    if effect_status == "established"
                    else (
                        "at least one complete path has principal-compatible guards but none for the performed effect"
                        if effect_status == "violated"
                        else "effect binding is unresolved on at least one protected-effect path"
                    )
                ),
                evidence_ids=sorted(all_effect_guards),
            )
        )

        effectiveness_status = _aggregate_path_status(effectiveness_statuses)
        effectiveness_evidence = sorted(
            {
                evidence_id
                for guard in all_effective_guards.values()
                for evidence_id in (
                    guard.effectiveness_evidence_ids or [guard.guard_id]
                )
            }
        )
        if not effectiveness_evidence and effectiveness_status != "established":
            effectiveness_evidence = sorted(all_effect_guards)
        checks.append(
            IntegrityCheck(
                dimension="guard_effectiveness",
                status=effectiveness_status,
                reason=(
                    "every protected-effect path has at least one principal/effect-compatible guard with proved authorization effectiveness"
                    if effectiveness_status == "established"
                    else "guard effectiveness is unproved or unresolved on at least one protected-effect path"
                ),
                evidence_ids=effectiveness_evidence,
            )
        )

        resource_status = _aggregate_path_status(resource_statuses)
        resource_evidence = sorted(
            {
                guard_id
                for guard_ids in path_exact_resource_guard_ids.values()
                for guard_id in guard_ids
            }
            | all_binding_ids
        )
        checks.append(
            IntegrityCheck(
                dimension="resource_binding",
                status=resource_status,
                reason=(
                    "every protected-effect path has an exact resource guard"
                    if resource_status == "established"
                    else (
                        "at least one complete path has compatible guards but no resource binding"
                        if resource_status == "violated"
                        else "one or more path-local resource bindings require verification"
                    )
                ),
                evidence_ids=resource_evidence,
            )
        )

        obligations.append(
            ProtectedEffectIntegrityObligation(
                obligation_id=f"pei:{effect.protected_effect_id}",
                claim_id=_matching_claim_id(ir, effect),
                protected_effect_id=effect.protected_effect_id,
                path_ids=sorted(path.path_id for path in paths),
                candidate_guard_ids=sorted(all_dominating_guards),
                resource_binding_ids=sorted(all_binding_ids),
                path_candidate_guard_ids={
                    key: value
                    for key, value in sorted(path_candidate_guard_ids.items())
                },
                path_exact_resource_guard_ids={
                    key: value
                    for key, value in sorted(
                        path_exact_resource_guard_ids.items()
                    )
                },
                path_resource_binding_ids={
                    key: value
                    for key, value in sorted(path_resource_binding_ids.items())
                },
                checks=checks,
                assumptions=[
                    "Assurance IR faithfully represents the supported source semantics.",
                    "Protected Effect Integrity is universal over represented effect paths and existential over qualifying guards within each path.",
                    "Conditional dominance is established only by exact source-grounded conjunctive condition atoms; no unstated Boolean equivalence is assumed.",
                ],
            )
        )

    return obligations
