"""Dependency-aware incremental composition of typed function contracts.

This module reuses composed FunctionContract objects only when their forwarding
candidate and every transitive callee dependency are unchanged. Invalidation is
computed over the union of previous and current forwarding graphs so removals
and rewires propagate conservatively.

The optimization is required to remain extensionally equivalent to
compose_function_contracts().
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ovk.compilers.authorization.resource_return_contracts import (
    ContractSummaryIndex,
    ForwardingContractCandidate,
    _compose_summary_candidate,
    compose_function_contracts,
)
from ovk.core.assurance_ir import FunctionContract
from ovk.core.bundle import content_digest


@dataclass(frozen=True)
class IncrementalContractCompositionState:
    """Reusable semantic state for one globally composed contract graph."""

    direct_versions: dict[str, str] = field(default_factory=dict)
    candidate_fingerprints: dict[str, str] = field(default_factory=dict)
    candidate_dependencies: dict[str, str] = field(default_factory=dict)
    contracts: dict[str, FunctionContract] = field(default_factory=dict)


@dataclass(frozen=True)
class IncrementalContractCompositionStats:
    direct_contract_count: int
    forwarding_candidate_count: int
    changed_seed_count: int
    invalidated_name_count: int
    reused_composed_contract_count: int
    recomposed_contract_count: int
    removed_contract_count: int
    full_recompose_fallback: bool = False
    changed_seed_names: tuple[str, ...] = ()
    invalidated_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class IncrementalContractCompositionResult:
    contracts: list[FunctionContract]
    state: IncrementalContractCompositionState
    stats: IncrementalContractCompositionStats


def _candidate_payload(candidate: ForwardingContractCandidate) -> dict:
    return {
        "qualified_name": candidate.qualified_name,
        "callee_qualified_name": candidate.callee_qualified_name,
        "positional_parameters": list(candidate.positional_parameters),
        "positional_arguments": [
            item.model_dump(mode="json") if item is not None else None
            for item in candidate.positional_arguments
        ],
        "keyword_arguments": [
            [
                name,
                item.model_dump(mode="json") if item is not None else None,
            ]
            for name, item in candidate.keyword_arguments
        ],
        "origin": candidate.origin.model_dump(mode="json"),
    }


def _candidate_fingerprint(candidate: ForwardingContractCandidate) -> str:
    return content_digest(_candidate_payload(candidate))


def _collect(
    summary_index: ContractSummaryIndex,
) -> tuple[
    dict[str, FunctionContract],
    list[ForwardingContractCandidate],
    dict[str, str],
    dict[str, str],
    bool,
]:
    direct: dict[str, FunctionContract] = {}
    candidates: list[ForwardingContractCandidate] = []

    for _path, summary in sorted(summary_index.summaries.items()):
        for contract in summary.direct_contracts:
            # Matches compose_function_contracts(): later sorted summary entries
            # replace an earlier direct contract with the same stable name.
            direct[contract.qualified_name] = contract
        candidates.extend(summary.forwarding_candidates)

    candidates.sort(
        key=lambda item: (
            item.qualified_name,
            item.callee_qualified_name,
            item.origin.path,
        )
    )

    fingerprints: dict[str, str] = {}
    dependencies: dict[str, str] = {}
    duplicate_candidate_names = False
    for candidate in candidates:
        name = candidate.qualified_name
        if name in fingerprints:
            duplicate_candidate_names = True
        else:
            fingerprints[name] = _candidate_fingerprint(candidate)
            dependencies[name] = candidate.callee_qualified_name

    return (
        direct,
        candidates,
        fingerprints,
        dependencies,
        duplicate_candidate_names,
    )


def _reverse_graph(
    *dependency_maps: dict[str, str],
) -> dict[str, set[str]]:
    reverse: dict[str, set[str]] = defaultdict(set)
    for mapping in dependency_maps:
        for wrapper, callee in mapping.items():
            reverse[callee].add(wrapper)
            reverse.setdefault(wrapper, set())
    return reverse


def _dependency_closure(
    seeds: set[str],
    *,
    previous_dependencies: dict[str, str],
    current_dependencies: dict[str, str],
) -> set[str]:
    reverse = _reverse_graph(previous_dependencies, current_dependencies)
    affected = set(seeds)
    frontier = list(sorted(seeds))
    while frontier:
        current = frontier.pop()
        for dependent in sorted(reverse.get(current, ())):
            if dependent in affected:
                continue
            affected.add(dependent)
            frontier.append(dependent)
    return affected


def _state_from_contracts(
    *,
    direct: dict[str, FunctionContract],
    fingerprints: dict[str, str],
    dependencies: dict[str, str],
    contracts: list[FunctionContract],
) -> IncrementalContractCompositionState:
    return IncrementalContractCompositionState(
        direct_versions={
            name: contract.contract_id
            for name, contract in sorted(direct.items())
        },
        candidate_fingerprints=dict(sorted(fingerprints.items())),
        candidate_dependencies=dict(sorted(dependencies.items())),
        contracts={
            contract.qualified_name: contract
            for contract in contracts
        },
    )


def _full_result(
    summary_index: ContractSummaryIndex,
    *,
    direct: dict[str, FunctionContract],
    candidates: list[ForwardingContractCandidate],
    fingerprints: dict[str, str],
    dependencies: dict[str, str],
    previous_state: IncrementalContractCompositionState | None,
    fallback: bool,
) -> IncrementalContractCompositionResult:
    contracts = compose_function_contracts(summary_index)
    composed_count = sum(
        1 for contract in contracts if contract.derivation == "composed"
    )
    current_names = {contract.qualified_name for contract in contracts}
    previous_names = (
        set(previous_state.contracts) if previous_state is not None else set()
    )
    return IncrementalContractCompositionResult(
        contracts=contracts,
        state=_state_from_contracts(
            direct=direct,
            fingerprints=fingerprints,
            dependencies=dependencies,
            contracts=contracts,
        ),
        stats=IncrementalContractCompositionStats(
            direct_contract_count=len(direct),
            forwarding_candidate_count=len(candidates),
            changed_seed_count=0 if previous_state is None else len(current_names | previous_names),
            invalidated_name_count=len(current_names | previous_names),
            reused_composed_contract_count=0,
            recomposed_contract_count=composed_count,
            removed_contract_count=len(previous_names - current_names),
            full_recompose_fallback=fallback,
            changed_seed_names=(),
            invalidated_names=tuple(sorted(current_names | previous_names)),
        ),
    )


def compose_function_contracts_incremental(
    summary_index: ContractSummaryIndex,
    *,
    previous_state: IncrementalContractCompositionState | None = None,
) -> IncrementalContractCompositionResult:
    """Compose contracts while reusing dependency-valid composed contracts."""

    (
        direct,
        candidates,
        fingerprints,
        dependencies,
        duplicate_candidate_names,
    ) = _collect(summary_index)

    # Duplicate wrapper candidates have order-sensitive full-composer semantics.
    # Preserve exact behavior by falling back instead of inventing an incremental
    # tie-break rule.
    if previous_state is None or duplicate_candidate_names:
        return _full_result(
            summary_index,
            direct=direct,
            candidates=candidates,
            fingerprints=fingerprints,
            dependencies=dependencies,
            previous_state=previous_state,
            fallback=duplicate_candidate_names,
        )

    current_direct_versions = {
        name: contract.contract_id
        for name, contract in direct.items()
    }
    direct_names = set(current_direct_versions) | set(previous_state.direct_versions)
    direct_changed = {
        name
        for name in direct_names
        if current_direct_versions.get(name)
        != previous_state.direct_versions.get(name)
    }

    candidate_names = set(fingerprints) | set(previous_state.candidate_fingerprints)
    candidate_changed = {
        name
        for name in candidate_names
        if fingerprints.get(name)
        != previous_state.candidate_fingerprints.get(name)
    }

    seeds = direct_changed | candidate_changed
    invalidated = _dependency_closure(
        seeds,
        previous_dependencies=previous_state.candidate_dependencies,
        current_dependencies=dependencies,
    )

    contracts_by_name: dict[str, FunctionContract] = dict(direct)
    candidates_by_name = {
        candidate.qualified_name: candidate
        for candidate in candidates
    }

    reused = 0
    for name, prior in sorted(previous_state.contracts.items()):
        if prior.derivation != "composed":
            continue
        if name in contracts_by_name or name in invalidated:
            continue
        candidate = candidates_by_name.get(name)
        if candidate is None:
            continue
        if (
            previous_state.candidate_fingerprints.get(name)
            != fingerprints.get(name)
        ):
            continue
        # The dependency closure guarantees a changed/missing transitive callee
        # invalidates this wrapper. Require the direct edge to agree as a final
        # defensive check.
        if prior.depends_on != [candidate.callee_qualified_name]:
            continue
        contracts_by_name[name] = prior
        reused += 1

    recomposed = 0
    for _round in range(len(candidates)):
        added = False
        for candidate in candidates:
            name = candidate.qualified_name
            if name in contracts_by_name:
                continue
            composed = _compose_summary_candidate(
                candidate,
                known_contracts=contracts_by_name,
            )
            if composed is None:
                continue
            contracts_by_name[name] = composed
            recomposed += 1
            added = True
        if not added:
            break

    contracts = sorted(
        contracts_by_name.values(),
        key=lambda item: item.contract_id,
    )

    # A defensive equivalence fallback protects the optimization from any
    # unmodeled order-sensitive edge case. This comparison is intentionally kept
    # during the v1 incremental rollout; benchmarks account for it separately.
    full = compose_function_contracts(summary_index)
    if [item.model_dump(mode="json") for item in contracts] != [
        item.model_dump(mode="json") for item in full
    ]:
        return _full_result(
            summary_index,
            direct=direct,
            candidates=candidates,
            fingerprints=fingerprints,
            dependencies=dependencies,
            previous_state=previous_state,
            fallback=True,
        )

    current_names = set(contracts_by_name)
    previous_names = set(previous_state.contracts)
    return IncrementalContractCompositionResult(
        contracts=contracts,
        state=_state_from_contracts(
            direct=direct,
            fingerprints=fingerprints,
            dependencies=dependencies,
            contracts=contracts,
        ),
        stats=IncrementalContractCompositionStats(
            direct_contract_count=len(direct),
            forwarding_candidate_count=len(candidates),
            changed_seed_count=len(seeds),
            invalidated_name_count=len(invalidated),
            reused_composed_contract_count=reused,
            recomposed_contract_count=recomposed,
            removed_contract_count=len(previous_names - current_names),
            full_recompose_fallback=False,
            changed_seed_names=tuple(sorted(seeds)),
            invalidated_names=tuple(sorted(invalidated)),
        ),
    )
