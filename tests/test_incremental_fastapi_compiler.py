from __future__ import annotations

from copy import deepcopy

from ovk.compilers.authorization.fastapi_route_summary import (
    build_route_summary_index,
)
from ovk.compilers.authorization.incremental_fastapi_compiler import (
    compile_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.python_ast_index import (
    parse_head_python_materials,
)
from ovk.compilers.authorization.resource_return_contracts import (
    build_contract_summary_index,
)


def _route_source() -> str:
    return """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    return await svc.get(agent_id, workspace_id=workspace_id)
""".strip()


def _service_source(attribute: str = "workspace_id") -> str:
    return f"""
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.{attribute} != workspace_id:
            return None
        return agent
""".strip()


def _files(
    *,
    service_attribute: str = "workspace_id",
    unrelated_value: int = 1,
) -> dict[str, str]:
    return {
        "routes.py": _route_source(),
        "service.py": _service_source(service_attribute),
        "unrelated.py": f"VALUE = {unrelated_value}\n",
        "more_unrelated.py": "OTHER = 2\n",
    }


def _materials(
    *,
    service_attribute: str = "workspace_id",
    unrelated_value: int = 1,
    head_revision: str = "head",
) -> AuthMaterials:
    files = _files(
        service_attribute=service_attribute,
        unrelated_value=unrelated_value,
    )
    return AuthMaterials(
        base_files=dict(files),
        head_files=files,
        repo="example/app",
        base_revision="base",
        head_revision=head_revision,
    )


def _profile(effect_name: str = "workspace.agent.read") -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects={"svc.get": effect_name},
        sink_identity_args={"svc.get": 0},
        sink_contracts={"svc.get": "AgentService.get"},
        sink_contract_scope_attributes={"svc.get": "workspace_id"},
        dependency_guard_resources={"require_workspace_member": "workspace_id"},
        dependency_guard_effects={
            "require_workspace_member": (effect_name,),
        },
        principal_parameter="user",
    )


def _indexes(materials: AuthMaterials):
    parsed = parse_head_python_materials(materials)
    contracts = build_contract_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    routes = build_route_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    return parsed, contracts, routes


def _incremental(materials, profile, previous_state=None):
    parsed, contracts, routes = _indexes(materials)
    return compile_incremental_fastapi_assurance(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes,
        previous_state=previous_state,
    )


def _full(materials, profile):
    parsed, contracts, routes = _indexes(materials)
    return FastApiDependencyEffectExtractor().compile(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes,
    )


def test_initial_incremental_compile_matches_full_compile() -> None:
    materials = _materials()
    profile = _profile()

    result = _incremental(materials, profile)
    full = _full(materials, profile)

    assert result.ir.canonical_payload() == full.canonical_payload()
    assert result.state.assurance_ir_digest == full.assurance_ir_digest
    assert result.stats.total_route_summary_files == 4
    assert result.stats.semantic_fragment_file_count == 1
    assert result.stats.rebound_file_count == 1
    assert result.stats.reused_fragment_count == 0


def test_unchanged_head_reuses_every_semantic_fragment() -> None:
    base = _materials(head_revision="base-head")
    first = _incremental(base, _profile())

    head = _materials(head_revision="next-head")
    second = _incremental(
        head,
        _profile(),
        previous_state=first.state,
    )
    full = _full(head, _profile())

    assert second.ir.canonical_payload() == full.canonical_payload()
    assert second.stats.semantic_fragment_file_count == 1
    assert second.stats.rebound_file_count == 0
    assert second.stats.reused_fragment_count == 1
    assert second.stats.changed_contract_count == 0


def test_unrelated_file_change_rebinds_only_that_file_fragment() -> None:
    base = _materials(unrelated_value=1, head_revision="base-head")
    first = _incremental(base, _profile())

    head = _materials(unrelated_value=2, head_revision="changed-unrelated")
    second = _incremental(
        head,
        _profile(),
        previous_state=first.state,
    )
    full = _full(head, _profile())

    assert second.ir.canonical_payload() == full.canonical_payload()
    assert second.stats.semantic_fragment_file_count == 1
    assert second.stats.rebound_file_count == 0
    assert second.stats.reused_fragment_count == 1
    assert second.stats.changed_contract_count == 0


def test_service_contract_change_rebinds_service_and_dependent_route_only() -> None:
    base = _materials(
        service_attribute="workspace_id",
        head_revision="base-head",
    )
    first = _incremental(base, _profile())
    assert first.ir.coverage.status == "complete"

    head = _materials(
        service_attribute="tenant_id",
        head_revision="changed-service",
    )
    second = _incremental(
        head,
        _profile(),
        previous_state=first.state,
    )
    full = _full(head, _profile())

    assert second.ir.canonical_payload() == full.canonical_payload()
    assert second.ir.coverage.status == "partial"
    assert second.stats.changed_contract_names == ("AgentService.get",)
    assert second.stats.semantic_fragment_file_count == 1
    assert second.stats.rebound_file_count == 1
    assert second.stats.reused_fragment_count == 0
    assert any(
        "required_scope_postcondition_missing:AgentService.get:workspace_id"
        in item
        for item in second.ir.coverage.unsupported_constructs
    )


def test_profile_change_rebinds_every_fragment_conservatively() -> None:
    materials = _materials()
    first = _incremental(materials, _profile())

    changed_profile = _profile("workspace.agent.inspect")
    second = _incremental(
        materials,
        changed_profile,
        previous_state=first.state,
    )
    full = _full(materials, changed_profile)

    assert second.ir.canonical_payload() == full.canonical_payload()
    assert second.stats.semantic_fragment_file_count == 1
    assert second.stats.rebound_file_count == 1
    assert second.stats.reused_fragment_count == 0
    assert [effect.name for effect in second.ir.effects] == [
        "workspace.agent.inspect"
    ]


def test_removed_file_is_reported_and_not_reused() -> None:
    base = _materials()
    first = _incremental(base, _profile())

    head = _materials(head_revision="removed-file")
    head.head_files.pop("more_unrelated.py")
    second = _incremental(
        head,
        _profile(),
        previous_state=first.state,
    )
    full = _full(head, _profile())

    assert second.ir.canonical_payload() == full.canonical_payload()
    assert second.stats.removed_fragment_count == 0
    assert second.stats.semantic_fragment_file_count == 1
    assert second.stats.reused_fragment_count == 1
    assert second.stats.rebound_file_count == 0


def test_fragment_reuse_is_bound_to_profile_and_contract_versions() -> None:
    base = _materials()
    first = _incremental(base, _profile())

    tampered = deepcopy(first.state.fragments["routes.py"])
    object.__setattr__(tampered, "profile_digest", "wrong")
    state = deepcopy(first.state)
    state.fragments["routes.py"] = tampered

    second = _incremental(
        base,
        _profile(),
        previous_state=state,
    )

    assert second.stats.rebound_file_count == 1
    assert second.stats.reused_fragment_count == 0



def _composed_files(repo_attribute: str = "workspace_id") -> dict[str, str]:
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
        "unrelated.py": "VALUE = 1\n",
    }


def _composed_materials(
    repo_attribute: str = "workspace_id",
    *,
    revision: str,
) -> AuthMaterials:
    files = _composed_files(repo_attribute)
    return AuthMaterials(
        base_files=dict(files),
        head_files=files,
        repo="example/composed-app",
        base_revision="base",
        head_revision=revision,
    )


def _composed_profile() -> FastApiDependencyEffectProfile:
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


def test_incremental_composition_and_fragment_reuse_share_dependency_closure() -> None:
    base = _composed_materials(revision="base-head")
    profile = _composed_profile()
    first = _incremental(base, profile)
    first_full = _full(base, profile)

    assert first.ir.canonical_payload() == first_full.canonical_payload()
    assert first.stats.recomposed_contract_count == 2
    assert first.stats.reused_composed_contract_count == 0

    unchanged = _composed_materials(revision="unchanged-head")
    second = _incremental(
        unchanged,
        profile,
        previous_state=first.state,
    )
    second_full = _full(unchanged, profile)

    assert second.ir.canonical_payload() == second_full.canonical_payload()
    assert second.stats.recomposed_contract_count == 0
    assert second.stats.reused_composed_contract_count == 2
    assert second.stats.semantic_fragment_file_count == 1
    assert second.stats.rebound_file_count == 0
    assert second.stats.reused_fragment_count == 1

    changed = _composed_materials(
        repo_attribute="tenant_id",
        revision="changed-repo-contract",
    )
    third = _incremental(
        changed,
        profile,
        previous_state=second.state,
    )
    third_full = _full(changed, profile)

    assert third.ir.canonical_payload() == third_full.canonical_payload()
    assert third.stats.changed_contract_names == (
        "AgentFacade.get",
        "AgentRepository.get",
        "AgentService.get",
    )
    assert third.stats.contract_invalidated_name_count == 3
    assert third.stats.recomposed_contract_count == 2
    assert third.stats.reused_composed_contract_count == 0
    assert third.stats.semantic_fragment_file_count == 1
    assert third.stats.rebound_file_count == 1
    assert third.stats.reused_fragment_count == 0

def _route_guard_files(auth_source: str) -> dict[str, str]:
    return {
        "routes.py": """
from fastapi import APIRouter, Depends
router = APIRouter()

@router.post("", dependencies=[Depends(require_auth)])
async def endpoint():
    await handle_jsonrpc_request({})
""".strip(),
        "security.py": auth_source.strip(),
    }


def _route_guard_materials(auth_source: str, *, revision: str) -> AuthMaterials:
    files = _route_guard_files(auth_source)
    return AuthMaterials(
        base_files=dict(files),
        head_files=files,
        repo="example/route-guard-incremental",
        base_revision="base",
        head_revision=revision,
    )


def _route_guard_profile() -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects={"handle_jsonrpc_request": "mcp.jsonrpc.dispatch"},
        sink_static_resources={
            "handle_jsonrpc_request": "mcp_transport"
        },
        route_dependency_guard_resources={
            "require_auth": "mcp_transport"
        },
        route_dependency_guard_effects={
            "require_auth": ("mcp.jsonrpc.dispatch",)
        },
        principal_parameter="$authenticated_caller",
    )


def test_dependency_body_change_invalidates_unchanged_route_fragment() -> None:
    secure = """
from fastapi import Depends

async def require_auth(credentials = Depends(_bearer_scheme)):
    if _active_token is None:
        raise HTTPException(status_code=503)
    if not credentials or credentials.credentials != _active_token:
        raise HTTPException(status_code=401)
"""
    fail_open = """
from fastapi import Depends

async def require_auth(credentials = Depends(_bearer_scheme)):
    if _active_token is None:
        return
    if not credentials or credentials.credentials != _active_token:
        raise HTTPException(status_code=401)
"""

    profile = _route_guard_profile()
    first_materials = _route_guard_materials(
        secure,
        revision="secure-head",
    )
    first = _incremental(first_materials, profile)
    assert first.ir.guards[0].effectiveness == "established"

    second_materials = _route_guard_materials(
        fail_open,
        revision="fail-open-head",
    )
    second = _incremental(
        second_materials,
        profile,
        previous_state=first.state,
    )
    full = _full(second_materials, profile)

    assert second.ir.canonical_payload() == full.canonical_payload()
    assert second.ir.guards[0].effectiveness == "unproved"
    assert second.stats.semantic_fragment_file_count == 1
    assert second.stats.rebound_file_count == 1
    assert second.stats.reused_fragment_count == 0

