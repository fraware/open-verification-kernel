from __future__ import annotations

from ovk.compilers.authorization.material_loader import materials_from_pair
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
