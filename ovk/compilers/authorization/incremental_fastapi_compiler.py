"""Incremental FastAPI Assurance IR compilation from reusable semantic fragments."""

from __future__ import annotations

from dataclasses import dataclass

from ovk.compilers.authorization.fastapi_route_summary import RouteSummaryIndex
from ovk.compilers.authorization.incremental_contract_composition import (
    IncrementalContractCompositionState,
    compose_function_contracts_incremental,
)
from ovk.compilers.authorization.fastapi_semantic_fragment import (
    FastApiFileSemanticFragment,
    assemble_fastapi_assurance_ir,
    bind_route_file_summary,
    fragment_dependencies_match,
    profile_semantic_digest,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.python_ast_index import (
    ParsedPythonMaterials,
    parsed_index_matches_materials,
)
from ovk.compilers.authorization.resource_return_contracts import (
    ContractSummaryIndex,
    contract_summary_index_matches_materials,
    infer_resource_return_contracts,
)
from ovk.core.assurance_ir import AssuranceIR


@dataclass(frozen=True)
class IncrementalFastApiCompilationState:
    """Reusable semantic state for one compiled head revision."""

    repo: str
    head_revision: str | None
    source_digests: dict[str, str]
    profile_digest: str
    contract_versions: dict[str, str]
    fragments: dict[str, FastApiFileSemanticFragment]
    assurance_ir_digest: str
    contract_composition_state: IncrementalContractCompositionState | None = None


@dataclass(frozen=True)
class IncrementalFastApiCompilationStats:
    """Deterministic work counts for one incremental semantic compile."""

    total_route_summary_files: int
    rebound_file_count: int
    reused_fragment_count: int
    removed_fragment_count: int
    changed_contract_count: int
    changed_contract_names: tuple[str, ...] = ()
    reused_composed_contract_count: int = 0
    recomposed_contract_count: int = 0
    contract_invalidated_name_count: int = 0


@dataclass(frozen=True)
class IncrementalFastApiCompilationResult:
    ir: AssuranceIR
    state: IncrementalFastApiCompilationState
    stats: IncrementalFastApiCompilationStats


def _validate_indexes(
    *,
    materials: AuthMaterials,
    parsed_index: ParsedPythonMaterials,
    contract_summary_index: ContractSummaryIndex,
    route_summary_index: RouteSummaryIndex,
) -> None:
    if not parsed_index_matches_materials(parsed_index, materials):
        raise ValueError(
            "parsed Python index does not match supplied head materials"
        )
    if not contract_summary_index_matches_materials(
        contract_summary_index,
        materials,
    ):
        raise ValueError(
            "contract summary index does not match supplied head materials"
        )
    from ovk.compilers.authorization.fastapi_route_summary import (
        route_summary_index_matches_materials,
    )

    if not route_summary_index_matches_materials(
        route_summary_index,
        materials,
    ):
        raise ValueError(
            "route summary index does not match supplied head materials"
        )


def _contract_versions(ir_contracts) -> dict[str, str]:
    return {
        contract.qualified_name: contract.contract_id
        for contract in ir_contracts
    }


def _changed_contract_names(
    previous: dict[str, str],
    current: dict[str, str],
) -> set[str]:
    names = set(previous) | set(current)
    return {
        name
        for name in names
        if previous.get(name) != current.get(name)
    }


def compile_incremental_fastapi_assurance(
    materials: AuthMaterials,
    profile: FastApiDependencyEffectProfile,
    *,
    parsed_index: ParsedPythonMaterials,
    contract_summary_index: ContractSummaryIndex,
    route_summary_index: RouteSummaryIndex,
    previous_state: IncrementalFastApiCompilationState | None = None,
) -> IncrementalFastApiCompilationResult:
    """Compile head Assurance IR while reusing dependency-valid file fragments."""

    _validate_indexes(
        materials=materials,
        parsed_index=parsed_index,
        contract_summary_index=contract_summary_index,
        route_summary_index=route_summary_index,
    )

    contract_composition = compose_function_contracts_incremental(
        contract_summary_index,
        previous_state=(
            previous_state.contract_composition_state
            if previous_state is not None
            else None
        ),
    )
    function_contracts = contract_composition.contracts
    resource_return_contracts = infer_resource_return_contracts(
        materials,
        function_contracts=function_contracts,
    )
    contracts_by_name = {
        contract.qualified_name: contract
        for contract in function_contracts
    }
    current_contract_versions = _contract_versions(function_contracts)
    current_profile_digest = profile_semantic_digest(profile)

    previous_contract_versions = (
        previous_state.contract_versions
        if previous_state is not None
        else {}
    )
    changed_contracts = _changed_contract_names(
        previous_contract_versions,
        current_contract_versions,
    )

    fragments: dict[str, FastApiFileSemanticFragment] = {}
    rebound = 0
    reused = 0

    for path, summary in sorted(route_summary_index.summaries.items()):
        prior = (
            previous_state.fragments.get(path)
            if previous_state is not None
            else None
        )
        if (
            prior is not None
            and prior.source_digest == summary.source_digest
            and fragment_dependencies_match(
                prior,
                profile=profile,
                contracts_by_name=contracts_by_name,
            )
        ):
            fragments[path] = prior
            reused += 1
            continue

        fragments[path] = bind_route_file_summary(
            summary,
            profile=profile,
            contracts_by_name=contracts_by_name,
        )
        rebound += 1

    previous_paths = (
        set(previous_state.fragments)
        if previous_state is not None
        else set()
    )
    removed = len(previous_paths - set(route_summary_index.summaries))

    missing_route_summaries = [
        path
        for path in sorted(materials.head_files)
        if path not in parsed_index.syntax_errors
        and path not in route_summary_index.summaries
    ]
    ir = assemble_fastapi_assurance_ir(
        materials=materials,
        function_contracts=function_contracts,
        resource_return_contracts=resource_return_contracts,
        fragments=fragments,
        syntax_errors=parsed_index.syntax_errors,
        missing_route_summary_paths=missing_route_summaries,
    )
    state = IncrementalFastApiCompilationState(
        repo=materials.repo or "unknown/repo",
        head_revision=materials.head_revision,
        source_digests=dict(route_summary_index.source_digests),
        profile_digest=current_profile_digest,
        contract_versions=current_contract_versions,
        fragments=fragments,
        assurance_ir_digest=ir.assurance_ir_digest,
        contract_composition_state=contract_composition.state,
    )
    return IncrementalFastApiCompilationResult(
        ir=ir,
        state=state,
        stats=IncrementalFastApiCompilationStats(
            total_route_summary_files=len(route_summary_index.summaries),
            rebound_file_count=rebound,
            reused_fragment_count=reused,
            removed_fragment_count=removed,
            changed_contract_count=len(changed_contracts),
            changed_contract_names=tuple(sorted(changed_contracts)),
            reused_composed_contract_count=(
                contract_composition.stats.reused_composed_contract_count
            ),
            recomposed_contract_count=(
                contract_composition.stats.recomposed_contract_count
            ),
            contract_invalidated_name_count=(
                contract_composition.stats.invalidated_name_count
            ),
        ),
    )
