"""Compile Assurance IR paths into protected-effect integrity obligations.

This compiler is source-model preserving: it does not claim that source extraction
is sound or that a binding holds. It turns one Assurance IR semantic path into a
backend-neutral obligation that makes principal/effect/resource binding and guard
coverage explicit.
"""

from __future__ import annotations

import json
from typing import Any

from ovk.core.assurance_ir import (
    AssuranceIR,
    BindingConstraint,
    SourceProvenance,
    compute_assurance_ir_digest,
)
from ovk.core.bundle import content_digest
from ovk.core.execution_models import (
    AbstractionCoverage,
    MaterialReference,
    VerificationObligation,
    compute_abstraction_digest,
    compute_obligation_id,
)
from ovk.core.models import RiskSeverity, SourceRange


COMPILER_ID = "ovk.assurance_ir.protected_effect_integrity.v1"
COMPILER_VERSION = "0.1.0"


def _severity(value: str) -> RiskSeverity:
    return RiskSeverity(value)


def _binding(
    ir: AssuranceIR,
    *,
    kind: str,
    left_ref: str,
    right_ref: str,
) -> dict[str, Any]:
    if left_ref == right_ref:
        return {
            "kind": kind,
            "left_ref": left_ref,
            "right_ref": right_ref,
            "binding_source": "identity",
            "binding_id": None,
            "declared_relation": "equal",
            "expression": None,
        }

    matches: list[BindingConstraint] = []
    for item in ir.bindings:
        if item.kind != kind:
            continue
        if {item.left_ref, item.right_ref} == {left_ref, right_ref}:
            matches.append(item)

    if len(matches) == 1:
        item = matches[0]
        return {
            "kind": kind,
            "left_ref": left_ref,
            "right_ref": right_ref,
            "binding_source": "explicit_constraint",
            "binding_id": item.binding_id,
            "declared_relation": item.relation,
            "expression": item.expression,
        }

    return {
        "kind": kind,
        "left_ref": left_ref,
        "right_ref": right_ref,
        "binding_source": "unresolved",
        "binding_id": None,
        "declared_relation": "unknown",
        "expression": None,
    }


def _unique_ranges(provenance: list[SourceProvenance]) -> list[SourceRange]:
    ranges: dict[tuple[Any, ...], SourceRange] = {}
    for item in provenance:
        for source_range in item.source_ranges:
            key = (
                source_range.path,
                source_range.start_line,
                source_range.end_line,
                source_range.start_column,
                source_range.end_column,
            )
            ranges[key] = source_range
    return [
        ranges[key]
        for key in sorted(
            ranges,
            key=lambda value: tuple("" if item is None else str(item) for item in value),
        )
    ]


def _coverage(ir: AssuranceIR, provenance: list[SourceProvenance]) -> AbstractionCoverage:
    statuses = [item.coverage for item in provenance]
    unknowns = list(ir.unknowns)
    if not provenance or "unknown" in statuses:
        status = "unknown"
        confidence = 0.0
    elif unknowns or "partial" in statuses:
        status = "partial"
        confidence = 0.5
    elif all(item == "complete" for item in statuses):
        status = "complete"
        confidence = 1.0
    else:
        status = "partial"
        confidence = 0.5

    warnings = sorted(
        {
            text
            for item in provenance
            for text in [*item.assumptions, *item.notes]
            if text
        }
    )
    return AbstractionCoverage(
        status=status,
        confidence=confidence,
        extracted_elements=len(provenance),
        expected_elements=len(provenance) if status == "complete" else None,
        unsupported_constructs=sorted(set(unknowns)),
        warnings=warnings,
        source_ranges=_unique_ranges(provenance),
    )


def _ir_material(ir: AssuranceIR) -> MaterialReference:
    digest = compute_assurance_ir_digest(ir)
    payload = json.dumps(
        ir.model_dump(mode="json", exclude={"ir_digest"}),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return MaterialReference(
        material_id=f"assurance-ir-{digest[:16]}",
        kind="generated_harness",
        uri=f"ovk-material:assurance-ir/{digest}",
        sha256=digest,
        size_bytes=len(payload),
        source_revision=ir.subject.head_sha,
        trusted=False,
    )


def compile_protected_effect_integrity(
    ir: AssuranceIR,
    *,
    policy_digest: str | None = None,
) -> list[VerificationObligation]:
    """Compile one obligation per semantic path ending in a protected effect."""

    principals = {item.principal_id: item for item in ir.principals}
    resources = {item.resource_id: item for item in ir.resources}
    effects = {item.effect_id: item for item in ir.effects}
    guards = {item.guard_id: item for item in ir.guards}
    protected = {item.protected_effect_id: item for item in ir.protected_effects}
    ir_digest = compute_assurance_ir_digest(ir)
    effective_policy_digest = policy_digest or content_digest(
        {"compiler": COMPILER_ID, "property_kind": "protected_effect_integrity"}
    )

    obligations: list[VerificationObligation] = []
    for path in ir.semantic_paths:
        sink = protected[path.protected_effect_ref]
        path_guards = [guards[ref] for ref in path.guard_refs]

        binding_requirements: list[dict[str, Any]] = []
        for guard in path_guards:
            binding_requirements.extend(
                [
                    _binding(
                        ir,
                        kind="principal",
                        left_ref=guard.principal_ref,
                        right_ref=sink.principal_ref,
                    ),
                    _binding(
                        ir,
                        kind="effect",
                        left_ref=guard.effect_ref,
                        right_ref=sink.effect_ref,
                    ),
                    _binding(
                        ir,
                        kind="resource",
                        left_ref=guard.resource_ref,
                        right_ref=sink.resource_ref,
                    ),
                ]
            )

        provenance = [
            path.provenance,
            sink.provenance,
            principals[sink.principal_ref].provenance,
            effects[sink.effect_ref].provenance,
            resources[sink.resource_ref].provenance,
            *[guard.provenance for guard in path_guards],
        ]
        for guard in path_guards:
            provenance.extend(
                [
                    principals[guard.principal_ref].provenance,
                    effects[guard.effect_ref].provenance,
                    resources[guard.resource_ref].provenance,
                ]
            )

        abstraction = {
            "kind": "protected_effect_integrity",
            "source_ir_digest": ir_digest,
            "path_id": path.path_id,
            "entrypoint": path.entrypoint,
            "protected_effect": sink.model_dump(mode="json"),
            "guard_requirement": {
                "meaning": "Every feasible path to the protected effect must pass an accepted authorization guard.",
                "guard_refs": list(path.guard_refs),
            },
            "binding_requirements": binding_requirements,
            "path_conditions": [
                condition.model_dump(mode="json")
                for condition in ir.path_conditions
                if condition.condition_id in set(path.condition_refs)
            ],
            "call_chain": list(path.call_chain),
        }
        coverage = _coverage(ir, provenance)
        provisional = VerificationObligation(
            obligation_id="pending",
            subject=ir.subject,
            intent_id=f"protected-effect-integrity:{sink.protected_effect_id}",
            intent_version="0.1.0",
            lane="authorization",
            property_kind="protected_effect_integrity",
            severity=_severity(sink.severity),
            compiler_id=COMPILER_ID,
            compiler_version=COMPILER_VERSION,
            materials=[_ir_material(ir)],
            abstraction=abstraction,
            abstraction_digest=compute_abstraction_digest(abstraction),
            coverage=coverage,
            acceptable_guarantees=["smt_refutation_search", "deterministic_witness"],
            required_capabilities=["authorization", "protected_effect_integrity"],
            policy_digest=effective_policy_digest,
        )
        obligations.append(
            provisional.model_copy(update={"obligation_id": compute_obligation_id(provisional)})
        )

    return obligations
