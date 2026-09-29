"""Incremental impact analysis for interprocedural assurance contracts.

Stable identity:
- FunctionContract.qualified_name identifies the callable across revisions.
- FunctionContract.contract_id identifies one semantic contract version.

The impact graph is intentionally independent of source file heuristics. It uses
only typed Assurance IR edges:
- FunctionContract.depends_on for contract-to-contract dependencies;
- ContractUse for concrete call-site consumption;
- SemanticPath.contract_use_ids for links to protected effects and bindings.

This keeps incremental invalidation deterministic and inspectable.
"""

from __future__ import annotations

from typing import Iterable

from pydantic import BaseModel, Field

from ovk.core.assurance_ir import AssuranceIR, FunctionContract


class ContractImpact(BaseModel):
    """Transitive assurance surface affected by one set of stable contract names."""

    seed_contracts: list[str] = Field(default_factory=list)
    unresolved_seeds: list[str] = Field(default_factory=list)
    affected_contracts: list[str] = Field(default_factory=list)
    affected_contract_uses: list[str] = Field(default_factory=list)
    affected_paths: list[str] = Field(default_factory=list)
    affected_protected_effects: list[str] = Field(default_factory=list)
    affected_bindings: list[str] = Field(default_factory=list)


class ContractDelta(BaseModel):
    """Stable-name contract delta between two Assurance IR revisions."""

    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    version_changed: list[str] = Field(default_factory=list)

    @property
    def changed_contracts(self) -> list[str]:
        return sorted(set(self.added) | set(self.removed) | set(self.version_changed))


class ContractDeltaImpact(BaseModel):
    """Revision-aware invalidation result over base and head contract graphs."""

    delta: ContractDelta
    base: ContractImpact
    head: ContractImpact
    affected_contracts: list[str] = Field(default_factory=list)
    affected_contract_uses: list[str] = Field(default_factory=list)
    affected_paths: list[str] = Field(default_factory=list)
    affected_protected_effects: list[str] = Field(default_factory=list)
    affected_bindings: list[str] = Field(default_factory=list)


def _contracts_by_name(ir: AssuranceIR) -> dict[str, FunctionContract]:
    return {contract.qualified_name: contract for contract in ir.function_contracts}


def _reverse_dependencies(ir: AssuranceIR) -> dict[str, set[str]]:
    """Map dependency stable name -> direct dependent stable names."""

    reverse: dict[str, set[str]] = {}
    for contract in ir.function_contracts:
        reverse.setdefault(contract.qualified_name, set())
        for dependency in contract.depends_on:
            reverse.setdefault(dependency, set()).add(contract.qualified_name)
    return reverse


def contract_dependency_closure(
    ir: AssuranceIR,
    seeds: Iterable[str],
) -> tuple[set[str], set[str]]:
    """Return transitive dependents and seeds absent from this revision.

    Seeds are included in the affected set when present. Unknown seeds are
    returned separately so removal cases remain explicit.
    """

    known = set(_contracts_by_name(ir))
    normalized = {seed.strip() for seed in seeds if seed.strip()}
    unresolved = normalized - known

    reverse = _reverse_dependencies(ir)
    affected = set(normalized & known)
    frontier = list(sorted(affected))

    while frontier:
        current = frontier.pop()
        for dependent in sorted(reverse.get(current, ())):
            if dependent in affected:
                continue
            affected.add(dependent)
            frontier.append(dependent)

    return affected, unresolved


def compute_contract_impact(
    ir: AssuranceIR,
    changed_contract_names: Iterable[str],
) -> ContractImpact:
    """Compute exact IR-level surfaces depending on changed stable contract names."""

    seeds = sorted({name.strip() for name in changed_contract_names if name.strip()})
    affected_contracts, unresolved = contract_dependency_closure(ir, seeds)

    affected_uses = {
        use.use_id
        for use in ir.contract_uses
        if use.qualified_name in affected_contracts
    }

    affected_paths = {
        path.path_id
        for path in ir.paths
        if affected_uses.intersection(path.contract_use_ids)
    }

    paths_by_id = {path.path_id: path for path in ir.paths}
    protected_effects: set[str] = set()
    bindings: set[str] = set()
    for path_id in affected_paths:
        path = paths_by_id[path_id]
        protected_effects.update(path.protected_effect_ids)
        bindings.update(path.binding_ids)

    return ContractImpact(
        seed_contracts=seeds,
        unresolved_seeds=sorted(unresolved),
        affected_contracts=sorted(affected_contracts),
        affected_contract_uses=sorted(affected_uses),
        affected_paths=sorted(affected_paths),
        affected_protected_effects=sorted(protected_effects),
        affected_bindings=sorted(bindings),
    )


def diff_function_contracts(base: AssuranceIR, head: AssuranceIR) -> ContractDelta:
    """Compare contract semantic versions by stable callable name."""

    before = _contracts_by_name(base)
    after = _contracts_by_name(head)
    before_names = set(before)
    after_names = set(after)

    common = before_names & after_names
    changed = {
        name
        for name in common
        if before[name].contract_id != after[name].contract_id
    }

    return ContractDelta(
        added=sorted(after_names - before_names),
        removed=sorted(before_names - after_names),
        version_changed=sorted(changed),
    )


def compute_contract_delta_impact(
    base: AssuranceIR,
    head: AssuranceIR,
) -> ContractDeltaImpact:
    """Compute conservative exact invalidation across both revision graphs.

    Both graphs are evaluated because a removed contract or removed call site is
    only representable in the base revision. The merged result therefore
    captures surfaces that disappeared as well as surfaces that still exist and
    require re-verification.
    """

    delta = diff_function_contracts(base, head)
    seeds = delta.changed_contracts
    base_impact = compute_contract_impact(base, seeds)
    head_impact = compute_contract_impact(head, seeds)

    return ContractDeltaImpact(
        delta=delta,
        base=base_impact,
        head=head_impact,
        affected_contracts=sorted(
            set(base_impact.affected_contracts) | set(head_impact.affected_contracts)
        ),
        affected_contract_uses=sorted(
            set(base_impact.affected_contract_uses) | set(head_impact.affected_contract_uses)
        ),
        affected_paths=sorted(
            set(base_impact.affected_paths) | set(head_impact.affected_paths)
        ),
        affected_protected_effects=sorted(
            set(base_impact.affected_protected_effects)
            | set(head_impact.affected_protected_effects)
        ),
        affected_bindings=sorted(
            set(base_impact.affected_bindings) | set(head_impact.affected_bindings)
        ),
    )
