from __future__ import annotations

from ovk.compilers.authorization.material_loader import AuthMaterials, materials_from_pair
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity


PROFILE = FastApiDependencyEffectProfile(
    sink_effects={"svc.get": "workspace.agent.read"},
    sink_identity_args={"svc.get": 0},
    sink_scope_keywords={"svc.get": "workspace_id"},
    sink_missing_scope_unconstrained=frozenset({"svc.get"}),
    dependency_guard_resources={"require_workspace_member": "workspace_id"},
    dependency_guard_effects={
        "require_workspace_member": ("workspace.agent.read",),
    },
    principal_parameter="user",
)


def _evaluate(source: str):
    materials = materials_from_pair(
        path="routes/agents.py",
        base_source=source,
        head_source=source,
        repo="example/platform",
        base_revision="base",
        head_revision="head",
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, PROFILE)
    result = evaluate_protected_effect_integrity(ir)[0]
    return ir, result


def test_dependency_guard_and_scoped_service_lookup_pass() -> None:
    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    agent = await svc.get(agent_id, workspace_id=workspace_id)
    return agent
""".strip()

    ir, result = _evaluate(source)

    assert ir.coverage.status == "complete"
    assert len(ir.guards) == 1
    assert len(ir.resource_bindings) == 1
    acted = next(resource for resource in ir.resources if resource.symbol == "agent_id")
    assert acted.identity_term is not None
    assert acted.identity_term.value == "agent_id"
    assert acted.scope_term is not None
    assert acted.scope_term.value == "workspace_id"
    assert result.status == "pass"


def test_dependency_guard_and_unscoped_service_lookup_refute_tenant_binding() -> None:
    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    agent = await svc.get(agent_id)
    return agent
""".strip()

    ir, result = _evaluate(source)

    assert ir.coverage.status == "complete"
    acted = next(resource for resource in ir.resources if resource.symbol == "agent_id")
    assert acted.scope_term is not None
    assert acted.scope_term.value.startswith("$scope:")
    assert result.status in {"fail", "unknown"}
    if result.status == "fail":
        assert result.resource_binding_evidence[0].counterexample is not None


def test_missing_workspace_dependency_is_violation() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(workspace_id: str, agent_id: str, user):
    svc = AgentService()
    agent = await svc.get(agent_id, workspace_id=workspace_id)
    return agent
""".strip()

    ir, result = _evaluate(source)

    assert ir.coverage.status == "complete"
    assert result.status == "fail"
    guard = next(check for check in result.checks if check.dimension == "guard_presence")
    assert guard.status == "violated"


def test_unmodeled_control_flow_forces_unknown_on_otherwise_safe_case() -> None:
    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
    enabled: bool = True,
):
    svc = AgentService()
    if enabled:
        audit(agent_id)
    agent = await svc.get(agent_id, workspace_id=workspace_id)
    return agent
""".strip()

    ir, result = _evaluate(source)

    assert ir.coverage.status == "partial"
    assert result.status == "unknown"



CONTRACT_PROFILE = FastApiDependencyEffectProfile(
    sink_effects={"svc.get": "workspace.agent.read"},
    sink_identity_args={"svc.get": 0},
    sink_contracts={"svc.get": "AgentService.get"},
    sink_contract_scope_attributes={"svc.get": "workspace_id"},
    dependency_guard_resources={"require_workspace_member": "workspace_id"},
    dependency_guard_effects={
        "require_workspace_member": ("workspace.agent.read",),
    },
    principal_parameter="user",
)


def _interprocedural_materials(
    route_source: str,
    service_source: str,
) -> AuthMaterials:
    return AuthMaterials(
        base_files={
            "routes/agents.py": route_source,
            "services/agent_service.py": service_source,
        },
        head_files={
            "routes/agents.py": route_source,
            "services/agent_service.py": service_source,
        },
        repo="example/platform",
        base_revision="base",
        head_revision="head",
    )


def test_inferred_service_contract_establishes_scope_binding() -> None:
    route_source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    agent = await svc.get(agent_id, workspace_id=workspace_id)
    return agent
""".strip()
    service_source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await self._session.get(Agent, agent_id)
        if agent is None:
            return None
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()

    ir = FastApiDependencyEffectExtractor().compile(
        _interprocedural_materials(route_source, service_source),
        CONTRACT_PROFILE,
    )
    result = evaluate_protected_effect_integrity(ir)[0]

    assert ir.coverage.status == "complete"
    assert len(ir.resource_return_contracts) == 1
    assert ir.resource_return_contracts[0].qualified_name == "AgentService.get"
    acted = next(resource for resource in ir.resources if resource.symbol == "agent_id")
    assert acted.scope_term is not None
    assert acted.scope_term.value == "workspace_id"
    assert result.status == "pass"


def test_omitted_scope_argument_under_inferred_contract_is_unconstrained() -> None:
    route_source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    agent = await svc.get(agent_id)
    return agent
""".strip()
    service_source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await self._session.get(Agent, agent_id)
        if agent is None:
            return None
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()

    ir = FastApiDependencyEffectExtractor().compile(
        _interprocedural_materials(route_source, service_source),
        CONTRACT_PROFILE,
    )
    result = evaluate_protected_effect_integrity(ir)[0]

    assert ir.coverage.status == "complete"
    acted = next(resource for resource in ir.resources if resource.symbol == "agent_id")
    assert acted.scope_term is not None
    assert acted.scope_term.value.startswith("$scope:")
    assert result.status in {"fail", "unknown"}


def test_missing_required_service_contract_forces_unknown() -> None:
    route_source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    agent = await svc.get(agent_id, workspace_id=workspace_id)
    return agent
""".strip()
    service_source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._session.get(Agent, agent_id)
""".strip()

    ir = FastApiDependencyEffectExtractor().compile(
        _interprocedural_materials(route_source, service_source),
        CONTRACT_PROFILE,
    )
    result = evaluate_protected_effect_integrity(ir)[0]

    assert ir.coverage.status == "partial"
    assert ir.resource_return_contracts == []
    assert any(
        "required_sink_contract_missing:AgentService.get" in item
        for item in ir.coverage.unsupported_constructs
    )
    assert result.status == "unknown"


def test_unproved_non_null_contract_precondition_forces_unknown() -> None:
    route_source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str | None,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    agent = await svc.get(agent_id, workspace_id=workspace_id)
    return agent
""".strip()
    service_source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await self._session.get(Agent, agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()

    ir = FastApiDependencyEffectExtractor().compile(
        _interprocedural_materials(route_source, service_source),
        CONTRACT_PROFILE,
    )
    result = evaluate_protected_effect_integrity(ir)[0]

    assert ir.coverage.status == "partial"
    assert any(
        "contract_precondition_unproved:AgentService.get:workspace_id" in item
        for item in ir.coverage.unsupported_constructs
    )
    assert result.status == "unknown"


def test_constructor_alias_mismatch_prevents_contract_consumption() -> None:
    route_source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = OtherService()
    agent = await svc.get(agent_id, workspace_id=workspace_id)
    return agent
""".strip()
    service_source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await self._session.get(Agent, agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()

    ir = FastApiDependencyEffectExtractor().compile(
        _interprocedural_materials(route_source, service_source),
        CONTRACT_PROFILE,
    )
    result = evaluate_protected_effect_integrity(ir)[0]

    assert ir.coverage.status == "partial"
    assert any(
        "sink_contract_target_unresolved:svc.get:AgentService.get" in item
        for item in ir.coverage.unsupported_constructs
    )
    assert result.status == "unknown"



IDENTITY_AND_SCOPE_PROFILE = FastApiDependencyEffectProfile(
    sink_effects={"svc.get": "workspace.agent.read"},
    sink_identity_args={"svc.get": 0},
    sink_contracts={"svc.get": "AgentService.get"},
    sink_contract_scope_attributes={"svc.get": "workspace_id"},
    sink_contract_identity_attributes={"svc.get": "id"},
    dependency_guard_resources={"require_workspace_member": "workspace_id"},
    dependency_guard_effects={
        "require_workspace_member": ("workspace.agent.read",),
    },
    principal_parameter="user",
)


def test_typed_contract_establishes_identity_and_scope_at_call_site() -> None:
    route_source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    agent = await svc.get(agent_id, workspace_id=workspace_id)
    return agent
""".strip()
    service_source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await self._session.get(Agent, agent_id)
        if agent.id != agent_id:
            return None
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()

    ir = FastApiDependencyEffectExtractor().compile(
        _interprocedural_materials(route_source, service_source),
        IDENTITY_AND_SCOPE_PROFILE,
    )
    result = evaluate_protected_effect_integrity(ir)[0]

    assert ir.coverage.status == "complete"
    assert len(ir.function_contracts) == 1
    acted = next(resource for resource in ir.resources if resource.symbol == "agent_id")
    assert acted.identity_term is not None
    assert acted.identity_term.value == "agent_id"
    assert acted.scope_term is not None
    assert acted.scope_term.value == "workspace_id"
    assert result.status == "pass"


def test_missing_required_identity_postcondition_forces_unknown() -> None:
    route_source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    agent = await svc.get(agent_id, workspace_id=workspace_id)
    return agent
""".strip()
    service_source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await self._session.get(Agent, agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()

    ir = FastApiDependencyEffectExtractor().compile(
        _interprocedural_materials(route_source, service_source),
        IDENTITY_AND_SCOPE_PROFILE,
    )
    result = evaluate_protected_effect_integrity(ir)[0]

    assert ir.coverage.status == "partial"
    assert any(
        "required_identity_postcondition_missing:AgentService.get:id" in item
        for item in ir.coverage.unsupported_constructs
    )
    acted = next(resource for resource in ir.resources if resource.symbol == "agent_id")
    assert acted.identity_term is None
    assert result.status == "unknown"



PROJECT_PARENT_PROFILE = FastApiDependencyEffectProfile(
    sink_effects={"svc.get": "project.document.read"},
    sink_identity_args={"svc.get": 0},
    sink_contracts={"svc.get": "DocumentService.get"},
    sink_binding_relations={"svc.get": "equal"},
    sink_binding_authorized_projections={"svc.get": "identity"},
    sink_binding_acted_projections={"svc.get": "attribute"},
    sink_binding_acted_attributes={"svc.get": "project_id"},
    dependency_guard_resources={"require_project_member": "project_id"},
    dependency_guard_effects={
        "require_project_member": ("project.document.read",),
    },
    principal_parameter="user",
)


def test_generic_contract_binds_authorized_parent_to_return_attribute() -> None:
    route_source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/projects/{project_id}/documents/{document_id}")
async def get_document(
    project_id: str,
    document_id: str,
    user = Depends(require_project_member),
):
    svc = DocumentService()
    document = await svc.get(document_id, project_id=project_id)
    return document
""".strip()
    service_source = """
class DocumentService:
    async def get(self, document_id: str, *, project_id: str):
        document = await load_document(document_id)
        if document.project_id != project_id:
            return None
        return document
""".strip()

    ir = FastApiDependencyEffectExtractor().compile(
        _interprocedural_materials(route_source, service_source),
        PROJECT_PARENT_PROFILE,
    )
    result = evaluate_protected_effect_integrity(ir)[0]

    assert ir.coverage.status == "complete"
    assert len(ir.function_contracts) == 1
    acted = next(
        resource for resource in ir.resources if resource.symbol == "document_id"
    )
    assert acted.attribute_terms["project_id"].value == "project_id"
    binding = ir.resource_bindings[0]
    assert binding.acted_projection == "attribute"
    assert binding.acted_attribute == "project_id"
    assert result.status == "pass"


def test_generic_parent_binding_refutes_wrong_parent_argument() -> None:
    route_source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/projects/{project_id}/documents/{document_id}")
async def get_document(
    project_id: str,
    other_project_id: str,
    document_id: str,
    user = Depends(require_project_member),
):
    svc = DocumentService()
    document = await svc.get(document_id, project_id=other_project_id)
    return document
""".strip()
    service_source = """
class DocumentService:
    async def get(self, document_id: str, *, project_id: str):
        document = await load_document(document_id)
        if document.project_id != project_id:
            return None
        return document
""".strip()

    ir = FastApiDependencyEffectExtractor().compile(
        _interprocedural_materials(route_source, service_source),
        PROJECT_PARENT_PROFILE,
    )
    result = evaluate_protected_effect_integrity(ir)[0]

    assert ir.coverage.status == "complete"
    acted = next(
        resource for resource in ir.resources if resource.symbol == "document_id"
    )
    assert acted.attribute_terms["project_id"].value == "other_project_id"
    assert result.status in {"fail", "unknown"}
    if result.status == "fail":
        evidence = result.resource_binding_evidence[0]
        assert evidence.counterexample is not None
        assert evidence.counterexample["acted_attribute"] == "project_id"
