"""Incremental semantic assurance planning.

This module determines which protected effects require semantic re-verification
between two Assurance IR revisions.

A protected effect is a semantic reuse candidate only when:
1. it exists in both revisions;
2. its complete semantic slice digest is unchanged; and
3. it is not affected by a changed interprocedural contract dependency.

This does not authorize reuse of backend evidence. Tool versions, environment
fingerprints, policy digests, and evidence expiry remain separate execution-plane
reuse conditions.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ovk.core.assurance_ir import AssuranceIR
from ovk.core.bundle import content_digest
from ovk.core.contract_impact import ContractDeltaImpact, compute_contract_delta_impact


class IncrementalAssurancePlan(BaseModel):
    """Semantic re-verification partition for one base/head transition."""

    base_assurance_ir_digest: str
    head_assurance_ir_digest: str
    contract_impact: ContractDeltaImpact

    reverify_effects: list[str] = Field(default_factory=list)
    semantic_reuse_candidates: list[str] = Field(default_factory=list)
    new_effects: list[str] = Field(default_factory=list)
    removed_effects: list[str] = Field(default_factory=list)
    changed_semantic_effects: list[str] = Field(default_factory=list)
    contract_affected_effects: list[str] = Field(default_factory=list)
    reverify_reasons: dict[str, list[str]] = Field(default_factory=dict)


def _index(items: list, identity_field: str) -> dict[str, object]:
    return {
        str(getattr(item, identity_field)): item
        for item in items
    }


def protected_effect_semantic_slice(ir: AssuranceIR, protected_effect_id: str) -> dict:
    """Return the canonical semantic slice supporting one protected effect.

    Subject revision SHAs are intentionally excluded: revision identity changing
    alone must not invalidate an otherwise identical semantic slice.

    Extractor/coverage/assumption context is included because the current
    Protected Effect evaluator requires complete extraction coverage for PASS.
    """

    protected_by_id = _index(ir.protected_effects, "protected_effect_id")
    protected = protected_by_id.get(protected_effect_id)
    if protected is None:
        raise ValueError(f"unknown protected effect: {protected_effect_id}")

    relevant_paths = sorted(
        [
            path
            for path in ir.paths
            if protected_effect_id in path.protected_effect_ids
        ],
        key=lambda item: item.path_id,
    )

    guard_ids = {
        guard_id
        for path in relevant_paths
        for guard_id in path.guard_ids
    }
    binding_ids = {
        binding_id
        for path in relevant_paths
        for binding_id in path.binding_ids
    }
    contract_use_ids = {
        use_id
        for path in relevant_paths
        for use_id in path.contract_use_ids
    }
    condition_ids = set(protected.condition_ids)
    for path in relevant_paths:
        condition_ids.update(path.condition_ids)

    guards_by_id = _index(ir.guards, "guard_id")
    bindings_by_id = _index(ir.resource_bindings, "binding_id")
    uses_by_id = _index(ir.contract_uses, "use_id")

    guards = [
        guards_by_id[guard_id]
        for guard_id in sorted(guard_ids)
        if guard_id in guards_by_id
    ]
    bindings = [
        bindings_by_id[binding_id]
        for binding_id in sorted(binding_ids)
        if binding_id in bindings_by_id
    ]
    uses = [
        uses_by_id[use_id]
        for use_id in sorted(contract_use_ids)
        if use_id in uses_by_id
    ]

    for guard in guards:
        condition_ids.update(guard.condition_ids)
    for binding in bindings:
        condition_ids.update(binding.condition_ids)

    resource_ids = {protected.resource_id}
    effect_ids = {protected.effect_id}
    principal_ids = {protected.principal_id}

    for guard in guards:
        resource_ids.add(guard.resource_id)
        effect_ids.add(guard.effect_id)
        principal_ids.add(guard.principal_id)

    for binding in bindings:
        resource_ids.add(binding.authorized_resource_id)
        resource_ids.add(binding.acted_resource_id)

    for use in uses:
        resource_ids.add(use.resource_id)

    resources_by_id = _index(ir.resources, "resource_id")
    effects_by_id = _index(ir.effects, "effect_id")
    principals_by_id = _index(ir.principals, "principal_id")
    conditions_by_id = _index(ir.conditions, "condition_id")

    contract_ids = {use.contract_id for use in uses}
    contracts = sorted(
        [
            contract
            for contract in ir.function_contracts
            if contract.contract_id in contract_ids
        ],
        key=lambda item: item.contract_id,
    )

    payload = {
        "extractor": ir.extractor.model_dump(mode="json"),
        "coverage": ir.coverage.model_dump(mode="json"),
        "assumptions": dict(sorted(ir.assumptions.items())),
        "protected_effect": protected.model_dump(mode="json"),
        "paths": [item.model_dump(mode="json") for item in relevant_paths],
        "guards": [
            guards_by_id[item].model_dump(mode="json")
            for item in sorted(guard_ids)
            if item in guards_by_id
        ],
        "bindings": [
            bindings_by_id[item].model_dump(mode="json")
            for item in sorted(binding_ids)
            if item in bindings_by_id
        ],
        "contract_uses": [
            uses_by_id[item].model_dump(mode="json")
            for item in sorted(contract_use_ids)
            if item in uses_by_id
        ],
        "contracts": [item.model_dump(mode="json") for item in contracts],
        "resources": [
            resources_by_id[item].model_dump(mode="json")
            for item in sorted(resource_ids)
            if item in resources_by_id
        ],
        "effects": [
            effects_by_id[item].model_dump(mode="json")
            for item in sorted(effect_ids)
            if item in effects_by_id
        ],
        "principals": [
            principals_by_id[item].model_dump(mode="json")
            for item in sorted(principal_ids)
            if item in principals_by_id
        ],
        "conditions": [
            conditions_by_id[item].model_dump(mode="json")
            for item in sorted(condition_ids)
            if item in conditions_by_id
        ],
    }
    return payload


def protected_effect_semantic_digest(ir: AssuranceIR, protected_effect_id: str) -> str:
    """Content digest of one protected effect's semantic support slice."""

    return content_digest(protected_effect_semantic_slice(ir, protected_effect_id))


def plan_incremental_assurance(
    base: AssuranceIR,
    head: AssuranceIR,
) -> IncrementalAssurancePlan:
    """Partition head protected effects into reverify and semantic-reuse candidates."""

    contract_impact = compute_contract_delta_impact(base, head)

    base_ids = {
        effect.protected_effect_id
        for effect in base.protected_effects
    }
    head_ids = {
        effect.protected_effect_id
        for effect in head.protected_effects
    }

    new_effects = head_ids - base_ids
    removed_effects = base_ids - head_ids
    common = base_ids & head_ids

    changed_semantic: set[str] = set()
    for effect_id in common:
        if (
            protected_effect_semantic_digest(base, effect_id)
            != protected_effect_semantic_digest(head, effect_id)
        ):
            changed_semantic.add(effect_id)

    contract_affected = (
        set(contract_impact.affected_protected_effects) & head_ids
    )

    reverify = new_effects | changed_semantic | contract_affected
    reuse_candidates = common - reverify

    reasons: dict[str, list[str]] = {}
    for effect_id in sorted(reverify):
        effect_reasons: list[str] = []
        if effect_id in new_effects:
            effect_reasons.append("new_protected_effect")
        if effect_id in changed_semantic:
            effect_reasons.append("semantic_slice_changed")
        if effect_id in contract_affected:
            effect_reasons.append("contract_dependency_changed")
        reasons[effect_id] = effect_reasons

    return IncrementalAssurancePlan(
        base_assurance_ir_digest=base.assurance_ir_digest,
        head_assurance_ir_digest=head.assurance_ir_digest,
        contract_impact=contract_impact,
        reverify_effects=sorted(reverify),
        semantic_reuse_candidates=sorted(reuse_candidates),
        new_effects=sorted(new_effects),
        removed_effects=sorted(removed_effects),
        changed_semantic_effects=sorted(changed_semantic),
        contract_affected_effects=sorted(contract_affected),
        reverify_reasons=reasons,
    )



def evaluate_incremental_reverification(
    head: AssuranceIR,
    plan: IncrementalAssurancePlan,
):
    """Evaluate only effects selected by a plan bound to this exact head IR.

    This executes fresh semantic verification for reverify_effects. It does not
    load or bless cached evidence for semantic_reuse_candidates.
    """

    if head.assurance_ir_digest != plan.head_assurance_ir_digest:
        raise ValueError(
            "incremental assurance plan head digest does not match supplied Assurance IR"
        )

    # Local import avoids coupling contract-impact construction to solver modules.
    from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity

    return evaluate_protected_effect_integrity(
        head,
        protected_effect_ids=plan.reverify_effects,
    )
