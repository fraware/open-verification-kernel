from __future__ import annotations

from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    AuthorizationGuard,
    EffectRef,
    PrincipalRef,
    ProtectedEffect,
    ResourceRef,
    SemanticOrigin,
    SemanticPath,
)
from ovk.core.models import VerificationSubject
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
        path="routes.py",
        base_source=source,
        head_source=source,
        repo="example/local-coverage",
        base_revision="base",
        head_revision="head",
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, PROFILE)
    results = evaluate_protected_effect_integrity(ir)
    return ir, results


def test_unrelated_unsupported_handler_does_not_poison_clean_effect() -> None:
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

@app.get("/unrelated")
async def unrelated(items: list[int] | None = None):
    for item in items or []:
        audit(item)
    return {"value": 1}
""".strip()

    ir, results = _evaluate(source)

    assert ir.coverage.status == "partial"
    assert len(results) == 1
    assert results[0].extraction_coverage == "complete"
    assert results[0].status == "pass"

    path = next(
        item
        for item in ir.paths
        if results[0].protected_effect_id in item.protected_effect_ids
    )
    assert path.coverage_status == "complete"
    assert path.unsupported_constructs == []


def test_unsupported_control_flow_before_sink_forces_local_unknown() -> None:
    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    tags: list[str] | None,
    user = Depends(require_workspace_member),
):
    for tag in tags or []:
        audit(agent_id, tag)
    svc = AgentService()
    agent = await svc.get(agent_id, workspace_id=workspace_id)
    return agent
""".strip()

    ir, results = _evaluate(source)

    assert ir.coverage.status == "partial"
    assert len(results) == 1
    assert results[0].extraction_coverage == "partial"
    assert results[0].status == "unknown"

    path = next(
        item
        for item in ir.paths
        if results[0].protected_effect_id in item.protected_effect_ids
    )
    assert path.coverage_status == "partial"
    assert any(
        "control_flow_before_protected_effect" in item
        for item in path.unsupported_constructs
    )


def test_unsupported_control_flow_after_sink_does_not_poison_effect() -> None:
    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    tags: list[str] | None,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    agent = await svc.get(agent_id, workspace_id=workspace_id)
    for tag in tags or []:
        audit(agent_id, tag)
    return agent
""".strip()

    ir, results = _evaluate(source)

    assert ir.coverage.status == "partial"
    assert len(results) == 1
    assert results[0].extraction_coverage == "complete"
    assert results[0].status == "pass"


def test_missing_path_local_coverage_falls_back_to_global_status() -> None:
    origin = SemanticOrigin(
        path="routes.py",
        extractor_id="legacy.test",
        extractor_version="0.1.0",
    )
    ir = AssuranceIR(
        subject=VerificationSubject(
            repo="example/legacy",
            base_sha="base",
            head_sha="head",
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="legacy.test",
            extractor_version="0.1.0",
        ),
        coverage=AssuranceCoverage(
            status="partial",
            confidence=0.5,
            unsupported_constructs=["legacy_global_gap"],
        ),
        principals=[
            PrincipalRef(
                principal_id="p:user",
                symbol="user",
                origin=origin,
            )
        ],
        resources=[
            ResourceRef(
                resource_id="r:item",
                symbol="item",
                origin=origin,
            )
        ],
        effects=[
            EffectRef(
                effect_id="e:read",
                name="item.read",
                origin=origin,
            )
        ],
        guards=[
            AuthorizationGuard(
                guard_id="g:read",
                principal_id="p:user",
                effect_id="e:read",
                resource_id="r:item",
                origin=origin,
            )
        ],
        protected_effects=[
            ProtectedEffect(
                protected_effect_id="pe:read",
                principal_id="p:user",
                effect_id="e:read",
                resource_id="r:item",
                origin=origin,
            )
        ],
        paths=[
            SemanticPath(
                path_id="path:read",
                entrypoint="GET /item",
                guard_ids=["g:read"],
                protected_effect_ids=["pe:read"],
                origin=origin,
            )
        ],
    )

    result = evaluate_protected_effect_integrity(ir)[0]
    assert result.extraction_coverage == "partial"
    assert result.status == "unknown"


def test_all_paths_for_effect_must_declare_local_coverage() -> None:
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
    return await svc.get(agent_id, workspace_id=workspace_id)

@app.get("/unrelated")
async def unrelated(items: list[int] | None = None):
    for item in items or []:
        audit(item)
    return 1
""".strip()
    ir, results = _evaluate(source)
    assert results[0].status == "pass"

    target = results[0].protected_effect_id
    path = next(
        item for item in ir.paths if target in item.protected_effect_ids
    )
    legacy_copy = path.model_copy(
        update={
            "path_id": "path:legacy-copy",
            "coverage_status": None,
            "unsupported_constructs": [],
            "coverage_assumptions": [],
        }
    )
    ir.paths.append(legacy_copy)

    reevaluated = evaluate_protected_effect_integrity(ir)[0]
    assert reevaluated.extraction_coverage == "partial"
    assert reevaluated.status == "unknown"
