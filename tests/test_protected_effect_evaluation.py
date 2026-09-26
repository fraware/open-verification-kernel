from __future__ import annotations

from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.protected_effect_fastapi import (
    FastApiProtectedEffectExtractor,
    ProtectedEffectProfile,
)
from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity


def _materials(source: str):
    return materials_from_pair(
        path="app.py",
        base_source=source,
        head_source=source,
        repo="example/workspaces",
        base_revision="base",
        head_revision="head",
    )


def _profile(*, unconstrained: bool = False) -> ProtectedEffectProfile:
    return ProtectedEffectProfile(
        sink_effects={"read_agent": "workspace.agent.read"},
        guard_functions=frozenset({"authorize_workspace"}),
        resource_loader_identity_args={
            "load_agent": 0,
            "load_agent_in_workspace": 1,
        },
        resource_loader_scope_args={"load_agent_in_workspace": 0},
        resource_loader_unconstrained_scopes=(
            frozenset({"load_agent"}) if unconstrained else frozenset()
        ),
        sink_binding_relations={"read_agent": "same_tenant"},
        sink_authorized_projections={"read_agent": "identity"},
        sink_acted_projections={"read_agent": "scope"},
    )


def test_scoped_resource_binding_yields_pass() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
def get_agent(workspace_id: str, agent_id: str, user):
    authorize_workspace(user, "workspace.agent.read", workspace_id)
    agent = load_agent_in_workspace(workspace_id, agent_id)
    read_agent(agent)
""".strip()

    ir = FastApiProtectedEffectExtractor().compile(_materials(source), _profile())
    result = evaluate_protected_effect_integrity(ir)[0]

    assert ir.coverage.status == "complete"
    assert result.status == "pass"
    binding = next(check for check in result.checks if check.dimension == "resource_binding")
    assert binding.status == "established"
    assert result.resource_binding_evidence[0].status == "pass"


def test_unconstrained_resource_scope_is_fail_when_solver_finds_counterexample() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
def get_agent(workspace_id: str, agent_id: str, user):
    authorize_workspace(user, "workspace.agent.read", workspace_id)
    agent = load_agent(agent_id)
    read_agent(agent)
""".strip()

    ir = FastApiProtectedEffectExtractor().compile(
        _materials(source),
        _profile(unconstrained=True),
    )

    def refuting_evaluator(_ir, binding):
        assert binding.relation == "same_tenant"
        return {
            "status": "fail",
            "reason": "counterexample exists",
            "counterexample": {
                "authorized": "workspace-a",
                "acted_scope": "workspace-b",
            },
        }

    result = evaluate_protected_effect_integrity(
        ir,
        resource_binding_evaluator=refuting_evaluator,
    )[0]

    assert result.status == "fail"
    assert "resource_binding" in result.reason
    assert result.resource_binding_evidence[0].counterexample is not None


def test_missing_solver_evidence_preserves_unknown() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
def get_agent(workspace_id: str, agent_id: str, user):
    authorize_workspace(user, "workspace.agent.read", workspace_id)
    agent = load_agent(agent_id)
    read_agent(agent)
""".strip()

    ir = FastApiProtectedEffectExtractor().compile(
        _materials(source),
        _profile(unconstrained=True),
    )

    result = evaluate_protected_effect_integrity(
        ir,
        resource_binding_evaluator=lambda _ir, _binding: {
            "status": "unknown",
            "reason": "solver unavailable",
            "counterexample": None,
        },
    )[0]

    assert result.status == "unknown"
    assert result.resource_binding_evidence[0].status == "unknown"


def test_partial_extraction_never_upgrades_to_pass() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
def get_agent(workspace_id: str, agent_id: str, user, enabled: bool):
    agent = load_agent_in_workspace(workspace_id, agent_id)
    if enabled:
        audit(agent)
    authorize_workspace(user, "workspace.agent.read", workspace_id)
    read_agent(agent)
""".strip()

    ir = FastApiProtectedEffectExtractor().compile(_materials(source), _profile())
    result = evaluate_protected_effect_integrity(ir)[0]

    assert ir.coverage.status == "partial"
    assert result.status == "unknown"
    assert "coverage is partial" in result.reason


def test_missing_guard_is_fail_even_when_coverage_complete() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
def get_agent(workspace_id: str, agent_id: str, user):
    agent = load_agent_in_workspace(workspace_id, agent_id)
    read_agent(agent)
""".strip()

    ir = FastApiProtectedEffectExtractor().compile(_materials(source), _profile())
    result = evaluate_protected_effect_integrity(ir)[0]

    assert ir.coverage.status == "complete"
    assert result.status == "fail"
    assert "guard_presence" in result.reason


def test_any_passing_candidate_binding_is_sufficient() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
def get_agent(workspace_id: str, agent_id: str, user, fallback_workspace_id: str):
    authorize_workspace(user, "workspace.agent.read", fallback_workspace_id)
    authorize_workspace(user, "workspace.agent.read", workspace_id)
    agent = load_agent_in_workspace(workspace_id, agent_id)
    read_agent(agent)
""".strip()

    ir = FastApiProtectedEffectExtractor().compile(_materials(source), _profile())

    statuses = iter(["fail", "pass"])

    def mixed_evaluator(_ir, _binding):
        status = next(statuses)
        return {
            "status": status,
            "reason": status,
            "counterexample": {"example": True} if status == "fail" else None,
        }

    result = evaluate_protected_effect_integrity(
        ir,
        resource_binding_evaluator=mixed_evaluator,
    )[0]

    assert len(result.resource_binding_evidence) == 2
    assert result.status == "pass"
