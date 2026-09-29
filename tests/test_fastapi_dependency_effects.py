from __future__ import annotations

from ovk.compilers.authorization.material_loader import AuthMaterials, materials_from_pair
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
    ResourceScopeAssertionSemantics,
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
    tags: list[str] | None = None,
):
    svc = AgentService()
    for tag in tags or []:
        audit(agent_id, tag)
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



COMPOSED_SCOPE_PROFILE = FastApiDependencyEffectProfile(
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


def test_route_consumes_service_contract_composed_from_repository_contract() -> None:
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
class AgentRepository:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent

class AgentService:
    def __init__(self):
        self._repo = AgentRepository()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._repo.get(agent_id, workspace_id=workspace_id)
""".strip()

    ir = FastApiDependencyEffectExtractor().compile(
        _interprocedural_materials(route_source, service_source),
        COMPOSED_SCOPE_PROFILE,
    )
    result = evaluate_protected_effect_integrity(ir)[0]
    by_name = {contract.qualified_name: contract for contract in ir.function_contracts}

    assert ir.coverage.status == "complete"
    assert "AgentRepository.get" in by_name
    assert "AgentService.get" in by_name
    acted = next(resource for resource in ir.resources if resource.symbol == "agent_id")
    assert acted.scope_term is not None
    assert acted.scope_term.value == "workspace_id"
    assert result.status == "pass"


def test_route_omitting_scope_still_refutes_composed_contract_binding() -> None:
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
class AgentRepository:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent

class AgentService:
    def __init__(self):
        self._repo = AgentRepository()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._repo.get(agent_id, workspace_id=workspace_id)
""".strip()

    ir = FastApiDependencyEffectExtractor().compile(
        _interprocedural_materials(route_source, service_source),
        COMPOSED_SCOPE_PROFILE,
    )
    result = evaluate_protected_effect_integrity(ir)[0]

    assert ir.coverage.status == "complete"
    acted = next(resource for resource in ir.resources if resource.symbol == "agent_id")
    assert acted.scope_term is not None
    assert acted.scope_term.value.startswith("$scope:")
    assert result.status in {"fail", "unknown"}



LITERAL_SCOPE_PROFILE = FastApiDependencyEffectProfile(
    sink_effects={"svc.get": "system.agent.read"},
    sink_identity_args={"svc.get": 0},
    sink_contracts={"svc.get": "SystemAgentService.get"},
    sink_contract_scope_attributes={"svc.get": "workspace_id"},
    principal_parameter="user",
)


def test_composed_literal_postcondition_instantiates_at_route_call_site() -> None:
    route_source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/system/agents/{agent_id}")
async def get_agent(agent_id: str, user):
    svc = SystemAgentService()
    agent = await svc.get(agent_id)
    return agent
""".strip()
    service_source = """
class AgentRepository:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent

class SystemAgentService:
    def __init__(self):
        self._repo = AgentRepository()

    async def get(self, agent_id: str):
        return await self._repo.get(agent_id, workspace_id="system")
""".strip()

    ir = FastApiDependencyEffectExtractor().compile(
        _interprocedural_materials(route_source, service_source),
        LITERAL_SCOPE_PROFILE,
    )
    by_name = {contract.qualified_name: contract for contract in ir.function_contracts}

    assert ir.coverage.status == "complete"
    assert "AgentRepository.get" in by_name
    assert "SystemAgentService.get" in by_name
    service_post = by_name["SystemAgentService.get"].postconditions[0]
    assert service_post.right is not None
    assert service_post.right.kind == "literal"
    assert service_post.right.value == "system"

    acted = next(resource for resource in ir.resources if resource.symbol == "agent_id")
    assert acted.scope_term is not None
    assert acted.scope_term.kind == "literal"
    assert acted.scope_term.value == "system"

ASSERTION_PROFILE = FastApiDependencyEffectProfile(
    sink_effects={
        "AgentResponse.model_validate": "workspace.agent.read",
    },
    sink_identity_args={"AgentResponse.model_validate": 0},
    sink_missing_scope_unconstrained=frozenset(
        {"AgentResponse.model_validate"}
    ),
    scope_assertions={
        "ensure_resource_in_workspace": ResourceScopeAssertionSemantics(
            acted_scope_arg=0,
            authorized_resource_arg=1,
            acted_scope_attribute="workspace_id",
        )
    },
    dependency_guard_resources={
        "require_workspace_member": "workspace_id",
    },
    dependency_guard_effects={
        "require_workspace_member": ("workspace.agent.read",),
    },
    principal_parameter="user",
)


def _evaluate_assertion_route(source: str):
    materials = materials_from_pair(
        path="routes/agents.py",
        base_source=source,
        head_source=source,
        repo="example/platform",
        base_revision="base",
        head_revision="head",
    )
    ir = FastApiDependencyEffectExtractor().compile(
        materials,
        ASSERTION_PROFILE,
    )
    results = evaluate_protected_effect_integrity(ir)
    assert len(results) == 1
    return ir, results[0]


def test_prior_resource_scope_assertion_establishes_response_binding() -> None:
    source = """
from fastapi import Depends, FastAPI, HTTPException
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    agent = await svc.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    ensure_resource_in_workspace(
        agent.workspace_id,
        workspace_id,
        label="Agent",
    )
    return AgentResponse.model_validate(agent)
""".strip()

    ir, result = _evaluate_assertion_route(source)

    assert ir.coverage.status == "complete"
    assert result.status == "pass"
    acted = next(
        resource for resource in ir.resources if resource.symbol == "agent"
    )
    assert acted.scope_term is not None
    assert acted.scope_term.value == "workspace_id"

    assertion_line = next(
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if "ensure_resource_in_workspace(" in line
    )
    binding = ir.resource_bindings[0]
    assert binding.origin.source_range is not None
    assert binding.origin.source_range.start_line == assertion_line


def test_missing_resource_scope_assertion_does_not_pass() -> None:
    source = """
from fastapi import Depends, FastAPI, HTTPException
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    agent = await svc.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return AgentResponse.model_validate(agent)
""".strip()

    ir, result = _evaluate_assertion_route(source)

    assert ir.coverage.status == "complete"
    acted = next(
        resource for resource in ir.resources if resource.symbol == "agent"
    )
    assert acted.scope_term is not None
    assert acted.scope_term.value.startswith("$scope:")
    assert result.status in {"fail", "unknown"}
    assert result.status != "pass"


def test_resource_scope_assertion_after_response_does_not_authorize_sink() -> None:
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
    response = AgentResponse.model_validate(agent)
    ensure_resource_in_workspace(
        agent.workspace_id,
        workspace_id,
        label="Agent",
    )
    return response
""".strip()

    ir, result = _evaluate_assertion_route(source)

    assert ir.coverage.status == "complete"
    acted = next(
        resource for resource in ir.resources if resource.symbol == "agent"
    )
    assert acted.scope_term is not None
    assert acted.scope_term.value.startswith("$scope:")
    assert result.status in {"fail", "unknown"}
    assert result.status != "pass"


def test_scope_assertion_for_other_resource_does_not_bind_acted_resource() -> None:
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
    ensure_resource_in_workspace(
        other_agent.workspace_id,
        workspace_id,
        label="Agent",
    )
    return AgentResponse.model_validate(agent)
""".strip()

    ir, result = _evaluate_assertion_route(source)

    assert ir.coverage.status == "complete"
    acted = next(
        resource for resource in ir.resources if resource.symbol == "agent"
    )
    assert acted.scope_term is not None
    assert acted.scope_term.value.startswith("$scope:")
    assert result.status in {"fail", "unknown"}
    assert result.status != "pass"


def test_arbitrary_control_flow_still_forces_unknown_with_assertion_profile() -> None:
    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
    tags: list[str] | None = None,
):
    svc = AgentService()
    agent = await svc.get(agent_id)
    for tag in tags or []:
        audit(agent_id, tag)
    ensure_resource_in_workspace(
        agent.workspace_id,
        workspace_id,
        label="Agent",
    )
    return AgentResponse.model_validate(agent)
""".strip()

    ir, result = _evaluate_assertion_route(source)

    assert ir.coverage.status == "partial"
    assert any(
        "cfg_unsupported:for" in item or "control_flow_outside_profile" in item
        for item in ir.coverage.unsupported_constructs
    )
    assert result.status == "unknown"

