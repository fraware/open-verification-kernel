from __future__ import annotations

import json

from ovk.compilers.authorization.persistent_fastapi_state import (
    PersistentFastApiIncrementalStateCache,
    compile_persistent_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.semantic_summary_cache import (
    PersistentPythonSemanticSummaryCache,
)
from ovk.core.bundle import content_digest


def _files(
    *,
    repo_attribute: str = "workspace_id",
    unrelated_value: int = 1,
) -> dict[str, str]:
    return {
        "routes.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentFacade()
    return await svc.get(agent_id, workspace_id=workspace_id)
""".strip(),
        "repo.py": f"""
class AgentRepository:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.{repo_attribute} != workspace_id:
            return None
        return agent
""".strip(),
        "service.py": """
class AgentService:
    def __init__(self):
        self._repo = AgentRepository()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._repo.get(agent_id, workspace_id=workspace_id)
""".strip(),
        "facade.py": """
class AgentFacade:
    def __init__(self):
        self._service = AgentService()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._service.get(agent_id, workspace_id=workspace_id)
""".strip(),
        "unrelated.py": f"VALUE = {unrelated_value}\n",
    }


def _materials(
    *,
    repo_attribute: str = "workspace_id",
    unrelated_value: int = 1,
    revision: str,
    repo: str | None = "example/persistent-fastapi",
) -> AuthMaterials:
    files = _files(
        repo_attribute=repo_attribute,
        unrelated_value=unrelated_value,
    )
    return AuthMaterials(
        base_files=dict(files),
        head_files=files,
        repo=repo,
        base_revision="base",
        head_revision=revision,
        repository_python_files=files,
        head_repository_python_files=files,
        base_repository_python_files=files,
    )


def _profile() -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects={"svc.get": "workspace.agent.read"},
        sink_identity_args={"svc.get": 0},
        sink_contracts={"svc.get": "AgentFacade.get"},
        sink_contract_scope_attributes={"svc.get": "workspace_id"},
        dependency_guard_resources={"require_workspace_member": "workspace_id"},
        dependency_guard_effects={
            "require_workspace_member": ("workspace.agent.read",),
        },
        principal_parameter="user",
    )


def _full(materials: AuthMaterials):
    return FastApiDependencyEffectExtractor().compile(
        materials,
        _profile(),
    )


def test_persistent_fastapi_state_round_trips_typed_state(tmp_path) -> None:
    summary_root = tmp_path / "summaries"
    state_root = tmp_path / "state"
    materials = _materials(revision="head-1")

    result = compile_persistent_incremental_fastapi_assurance(
        materials,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )
    state = result.compilation.state
    loaded = PersistentFastApiIncrementalStateCache(state_root).get(
        repo=state.repo,
        profile_digest=state.profile_digest,
    )

    assert loaded is not None
    assert loaded.repo == state.repo
    assert loaded.head_revision == state.head_revision
    assert loaded.source_digests == state.source_digests
    assert loaded.contract_versions == state.contract_versions
    assert loaded.assurance_ir_digest == state.assurance_ir_digest
    assert set(loaded.fragments) == set(state.fragments)
    assert loaded.contract_composition_state is not None
    assert state.contract_composition_state is not None
    assert (
        loaded.contract_composition_state.candidate_dependencies
        == state.contract_composition_state.candidate_dependencies
    )
    assert (
        loaded.contract_composition_state.contracts.keys()
        == state.contract_composition_state.contracts.keys()
    )
    # #157 persisted fields must survive the 0.62.0 round-trip.
    assert loaded.head_repository_python_manifest_digest is not None
    assert (
        loaded.head_repository_python_manifest_digest
        == state.head_repository_python_manifest_digest
    )
    assert (
        loaded.derived_closed_world_scope_digest
        == state.derived_closed_world_scope_digest
    )


def test_old_persistent_fastapi_state_implementation_version_is_cache_miss(
    tmp_path,
) -> None:
    """0.61.0 key identity must not load under 0.62.0 (#173)."""

    from ovk.compilers.authorization.persistent_fastapi_state import (
        PERSISTENT_FASTAPI_STATE_IMPLEMENTATION_VERSION,
        _key_components,
    )

    assert PERSISTENT_FASTAPI_STATE_IMPLEMENTATION_VERSION == "0.62.0"

    summary_root = tmp_path / "summaries"
    state_root = tmp_path / "state"
    materials = _materials(revision="head-1")
    state_cache = PersistentFastApiIncrementalStateCache(state_root)

    result = compile_persistent_incremental_fastapi_assurance(
        materials,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=state_cache,
    )
    state = result.compilation.state
    cache_path = state_cache._path(
        repo=state.repo,
        profile_digest=state.profile_digest,
    )
    record = json.loads(cache_path.read_text(encoding="utf-8"))
    # Forge a pre-audit implementation version inside the current key file.
    record["key_components"]["implementation_version"] = "0.61.0"
    record["key_digest"] = content_digest(record["key_components"])
    cache_path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert state_cache.get(
        repo=state.repo,
        profile_digest=state.profile_digest,
    ) is None
    # Current key components still advertise 0.62.0.
    assert (
        _key_components(
            repo=state.repo,
            profile_digest=state.profile_digest,
        )["implementation_version"]
        == "0.62.0"
    )


def test_corrupt_or_internally_inconsistent_persistent_state_is_cache_miss(
    tmp_path,
) -> None:
    summary_root = tmp_path / "summaries"
    state_root = tmp_path / "state"
    materials = _materials(revision="head-1")
    state_cache = PersistentFastApiIncrementalStateCache(state_root)

    result = compile_persistent_incremental_fastapi_assurance(
        materials,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=state_cache,
    )
    state = result.compilation.state
    cache_path = state_cache._path(
        repo=state.repo,
        profile_digest=state.profile_digest,
    )

    record = json.loads(cache_path.read_text(encoding="utf-8"))
    record["payload"]["assurance_ir_digest"] = "tampered"
    cache_path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert state_cache.get(
        repo=state.repo,
        profile_digest=state.profile_digest,
    ) is None

    # Restore a valid record, then make the payload self-digesting but
    # internally inconsistent. Typed/state validation must still reject it.
    state_cache.put(state)
    record = json.loads(cache_path.read_text(encoding="utf-8"))
    record["payload"]["contract_versions"]["AgentFacade.get"] = "wrong"
    record["payload_digest"] = content_digest(record["payload"])
    cache_path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert state_cache.get(
        repo=state.repo,
        profile_digest=state.profile_digest,
    ) is None


def test_fresh_worker_unchanged_head_reuses_all_higher_level_state(
    tmp_path,
) -> None:
    summary_root = tmp_path / "summaries"
    state_root = tmp_path / "state"

    base = _materials(revision="head-1")
    first = compile_persistent_incremental_fastapi_assurance(
        base,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )
    assert first.previous_state_loaded is False
    assert first.semantic_summary_stats.parse_count == 5
    assert first.state_written is True

    # Fresh cache objects simulate a new worker/process.
    head = _materials(revision="head-2")
    second = compile_persistent_incremental_fastapi_assurance(
        head,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )
    full = _full(head)

    assert second.compilation.ir.canonical_payload() == full.canonical_payload()
    assert second.previous_state_loaded is True
    assert second.semantic_summary_stats.parse_count == 0
    assert second.semantic_summary_stats.hits == 5
    assert second.compilation.stats.recomposed_contract_count == 0
    assert second.compilation.stats.reused_composed_contract_count == 2
    assert second.compilation.stats.semantic_fragment_file_count == 1
    assert second.compilation.stats.rebound_file_count == 0
    assert second.compilation.stats.reused_fragment_count == 1


def test_fresh_worker_unrelated_change_recomputes_one_file_only(
    tmp_path,
) -> None:
    summary_root = tmp_path / "summaries"
    state_root = tmp_path / "state"

    base = _materials(unrelated_value=1, revision="head-1")
    compile_persistent_incremental_fastapi_assurance(
        base,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )

    head = _materials(unrelated_value=2, revision="head-2")
    second = compile_persistent_incremental_fastapi_assurance(
        head,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )
    full = _full(head)

    assert second.compilation.ir.canonical_payload() == full.canonical_payload()
    assert second.previous_state_loaded is True
    assert second.semantic_summary_stats.parse_count == 1
    assert second.semantic_summary_stats.hits == 4
    assert second.compilation.stats.recomposed_contract_count == 0
    assert second.compilation.stats.reused_composed_contract_count == 2
    assert second.compilation.stats.semantic_fragment_file_count == 1
    assert second.compilation.stats.rebound_file_count == 0
    assert second.compilation.stats.reused_fragment_count == 1


def test_fresh_worker_contract_change_recomputes_dependency_closure(
    tmp_path,
) -> None:
    summary_root = tmp_path / "summaries"
    state_root = tmp_path / "state"

    base = _materials(
        repo_attribute="workspace_id",
        revision="head-1",
    )
    compile_persistent_incremental_fastapi_assurance(
        base,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )

    head = _materials(
        repo_attribute="tenant_id",
        revision="head-2",
    )
    second = compile_persistent_incremental_fastapi_assurance(
        head,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )
    full = _full(head)

    assert second.compilation.ir.canonical_payload() == full.canonical_payload()
    assert second.previous_state_loaded is True
    assert second.semantic_summary_stats.parse_count == 1
    assert second.semantic_summary_stats.hits == 4
    assert second.compilation.stats.recomposed_contract_count == 2
    assert second.compilation.stats.contract_invalidated_name_count == 3
    assert second.compilation.stats.semantic_fragment_file_count == 1
    assert second.compilation.stats.rebound_file_count == 1
    assert second.compilation.stats.reused_fragment_count == 0


def test_missing_repo_identity_disables_higher_level_state_persistence(
    tmp_path,
) -> None:
    summary_root = tmp_path / "summaries"
    state_root = tmp_path / "state"
    materials = _materials(revision="head-1", repo=None)

    result = compile_persistent_incremental_fastapi_assurance(
        materials,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )

    assert result.previous_state_loaded is False
    assert result.state_written is False
    assert list(state_root.glob("*.json")) == []

def _persistent_include_router_files(*, guarded: bool) -> dict[str, str]:
    dependency = (
        ", dependencies=[Depends(require_auth)]"
        if guarded
        else ""
    )
    return {
        "app/main.py": f"""
from fastapi import Depends, FastAPI
from app.endpoints import stats

app = FastAPI()
app.include_router(stats.router{dependency})
""".strip(),
        "app/endpoints/stats.py": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/sample")
async def sample():
    return protected_call()
""".strip(),
    }


def _persistent_include_router_materials(
    *,
    guarded: bool,
    revision: str,
) -> AuthMaterials:
    files = _persistent_include_router_files(guarded=guarded)
    return AuthMaterials(
        base_files=dict(files),
        head_files=files,
        repo="example/persistent-include-router",
        base_revision="base",
        head_revision=revision,
    )


def _persistent_include_router_profile() -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects={"protected_call": "stats.sample.generate"},
        sink_static_resources={
            "protected_call": "stats_sampling_service"
        },
        route_dependency_guard_resources={
            "require_auth": "stats_sampling_service"
        },
        route_dependency_guard_effects={
            "require_auth": ("stats.sample.generate",)
        },
        principal_parameter="$api_key_caller",
    )


def test_fresh_worker_include_router_change_rebinds_cached_target(
    tmp_path,
) -> None:
    summary_root = tmp_path / "summaries"
    state_root = tmp_path / "state"
    profile = _persistent_include_router_profile()

    base = _persistent_include_router_materials(
        guarded=False,
        revision="head-1",
    )
    first = compile_persistent_incremental_fastapi_assurance(
        base,
        profile,
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )
    assert first.compilation.ir.guards == []

    head = _persistent_include_router_materials(
        guarded=True,
        revision="head-2",
    )
    second = compile_persistent_incremental_fastapi_assurance(
        head,
        profile,
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )
    full = FastApiDependencyEffectExtractor().compile(head, profile)

    assert second.compilation.ir.canonical_payload() == full.canonical_payload()
    assert second.previous_state_loaded is True
    assert second.semantic_summary_stats.parse_count == 1
    assert second.semantic_summary_stats.hits == 1
    assert second.compilation.stats.rebound_file_count == 1
    assert second.compilation.stats.reused_fragment_count == 0
    assert len(second.compilation.ir.guards) == 1
    assert second.compilation.ir.guards[0].effectiveness == "unproved"

