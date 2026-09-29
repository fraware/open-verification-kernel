from __future__ import annotations

from ovk.compilers.authorization.incremental_contract_composition import (
    compose_function_contracts_incremental,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.python_ast_index import parse_head_python_materials
from ovk.compilers.authorization.resource_return_contracts import (
    build_contract_summary_index,
    compose_function_contracts,
)


def _repo(name: str, attribute: str = "scope_id") -> str:
    return f"""
class {name}:
    async def get(self, item_id: str, *, scope_id: str | None = None):
        item = await load_item(item_id)
        if scope_id is not None and item.{attribute} != scope_id:
            return None
        return item
""".strip()


def _wrapper(name: str, callee: str) -> str:
    return f"""
class {name}:
    def __init__(self):
        self._inner = {callee}()

    async def get(self, item_id: str, *, scope_id: str | None = None):
        return await self._inner.get(item_id, scope_id=scope_id)
""".strip()


def _files(
    *,
    repo_a_attribute: str = "scope_id",
    service_a_callee: str = "RepoA",
    include_repo_a: bool = True,
) -> dict[str, str]:
    files = {
        "service_a.py": _wrapper("ServiceA", service_a_callee),
        "facade_a.py": _wrapper("FacadeA", "ServiceA"),
        "repo_b.py": _repo("RepoB"),
        "service_b.py": _wrapper("ServiceB", "RepoB"),
        "unrelated.py": "VALUE = 1\n",
    }
    if include_repo_a:
        files["repo_a.py"] = _repo("RepoA", repo_a_attribute)
    return files


def _materials(files: dict[str, str], revision: str) -> AuthMaterials:
    return AuthMaterials(
        base_files=dict(files),
        head_files=dict(files),
        repo="example/contracts",
        base_revision="base",
        head_revision=revision,
    )


def _summary(files: dict[str, str], revision: str):
    materials = _materials(files, revision)
    parsed = parse_head_python_materials(materials)
    summary = build_contract_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    return summary


def _payload(contracts):
    return [item.model_dump(mode="json") for item in contracts]


def test_initial_incremental_composition_matches_full() -> None:
    summary = _summary(_files(), "head-1")

    result = compose_function_contracts_incremental(summary)
    full = compose_function_contracts(summary)

    assert _payload(result.contracts) == _payload(full)
    assert result.stats.reused_composed_contract_count == 0
    assert result.stats.recomposed_contract_count == 3
    assert result.stats.full_recompose_fallback is False


def test_unchanged_graph_reuses_every_composed_contract() -> None:
    summary = _summary(_files(), "head-1")
    first = compose_function_contracts_incremental(summary)

    same = _summary(_files(), "head-2")
    second = compose_function_contracts_incremental(
        same,
        previous_state=first.state,
    )
    full = compose_function_contracts(same)

    assert _payload(second.contracts) == _payload(full)
    assert second.stats.changed_seed_count == 0
    assert second.stats.invalidated_name_count == 0
    assert second.stats.reused_composed_contract_count == 3
    assert second.stats.recomposed_contract_count == 0


def test_leaf_direct_change_recomposes_only_transitive_dependents() -> None:
    first_summary = _summary(_files(), "head-1")
    first = compose_function_contracts_incremental(first_summary)

    changed_summary = _summary(
        _files(repo_a_attribute="tenant_id"),
        "head-2",
    )
    second = compose_function_contracts_incremental(
        changed_summary,
        previous_state=first.state,
    )
    full = compose_function_contracts(changed_summary)

    assert _payload(second.contracts) == _payload(full)
    assert second.stats.changed_seed_names == ("RepoA.get",)
    assert second.stats.invalidated_names == (
        "FacadeA.get",
        "RepoA.get",
        "ServiceA.get",
    )
    assert second.stats.reused_composed_contract_count == 1
    assert second.stats.recomposed_contract_count == 2


def test_forwarding_rewire_invalidates_wrapper_and_its_dependents_only() -> None:
    first_summary = _summary(_files(), "head-1")
    first = compose_function_contracts_incremental(first_summary)

    rewired_summary = _summary(
        _files(service_a_callee="RepoB"),
        "head-2",
    )
    second = compose_function_contracts_incremental(
        rewired_summary,
        previous_state=first.state,
    )
    full = compose_function_contracts(rewired_summary)

    assert _payload(second.contracts) == _payload(full)
    assert second.stats.changed_seed_names == ("ServiceA.get",)
    assert second.stats.invalidated_names == (
        "FacadeA.get",
        "ServiceA.get",
    )
    assert second.stats.reused_composed_contract_count == 1
    assert second.stats.recomposed_contract_count == 2


def test_removed_direct_contract_removes_unprovable_dependency_chain() -> None:
    first_summary = _summary(_files(), "head-1")
    first = compose_function_contracts_incremental(first_summary)

    removed_summary = _summary(
        _files(include_repo_a=False),
        "head-2",
    )
    second = compose_function_contracts_incremental(
        removed_summary,
        previous_state=first.state,
    )
    full = compose_function_contracts(removed_summary)

    assert _payload(second.contracts) == _payload(full)
    assert second.stats.changed_seed_names == ("RepoA.get",)
    assert second.stats.invalidated_names == (
        "FacadeA.get",
        "RepoA.get",
        "ServiceA.get",
    )
    assert second.stats.reused_composed_contract_count == 1
    assert second.stats.recomposed_contract_count == 0
    assert second.stats.removed_contract_count == 3


def test_initial_fallback_is_only_initialization_not_duplicate_fallback() -> None:
    summary = _summary(_files(), "head-1")
    result = compose_function_contracts_incremental(summary)

    assert result.stats.full_recompose_fallback is False
