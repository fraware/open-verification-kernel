from __future__ import annotations

from copy import deepcopy

import pytest

from ovk.compilers.authorization.material_loader import AuthMaterials
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
from ovk.core.incremental_assurance import (
    evaluate_incremental_reverification,
    plan_incremental_assurance,
    protected_effect_semantic_digest,
)
from ovk.core.models import VerificationSubject
from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity
from ovk.core.resource_identity import ResourceIdentityTerm


def _origin(path: str) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="test.extractor",
        extractor_version="0.1.0",
    )


def _two_effect_ir() -> AssuranceIR:
    return AssuranceIR(
        subject=VerificationSubject(
            repo="example/app",
            base_sha="base",
            head_sha="head",
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test.extractor",
            extractor_version="0.1.0",
        ),
        coverage=AssuranceCoverage(status="complete", confidence=1.0),
        principals=[
            PrincipalRef(
                principal_id="p:user",
                symbol="user",
                origin=_origin("app.py"),
            )
        ],
        resources=[
            ResourceRef(
                resource_id="r:invoice",
                symbol="invoice",
                identity_term=ResourceIdentityTerm.symbol("invoice_id"),
                origin=_origin("billing.py"),
            ),
            ResourceRef(
                resource_id="r:account",
                symbol="account",
                identity_term=ResourceIdentityTerm.symbol("account_id"),
                origin=_origin("accounts.py"),
            ),
        ],
        effects=[
            EffectRef(
                effect_id="e:refund",
                name="billing.invoice.refund",
                origin=_origin("billing.py"),
            ),
            EffectRef(
                effect_id="e:delete",
                name="identity.account.delete",
                origin=_origin("accounts.py"),
            ),
        ],
        guards=[
            AuthorizationGuard(
                guard_id="g:refund",
                principal_id="p:user",
                effect_id="e:refund",
                resource_id="r:invoice",
                origin=_origin("billing.py"),
            ),
            AuthorizationGuard(
                guard_id="g:delete",
                principal_id="p:user",
                effect_id="e:delete",
                resource_id="r:account",
                origin=_origin("accounts.py"),
            ),
        ],
        protected_effects=[
            ProtectedEffect(
                protected_effect_id="pe:refund",
                principal_id="p:user",
                effect_id="e:refund",
                resource_id="r:invoice",
                origin=_origin("billing.py"),
            ),
            ProtectedEffect(
                protected_effect_id="pe:delete",
                principal_id="p:user",
                effect_id="e:delete",
                resource_id="r:account",
                origin=_origin("accounts.py"),
            ),
        ],
        paths=[
            SemanticPath(
                path_id="path:refund",
                entrypoint="POST /refund",
                guard_ids=["g:refund"],
                protected_effect_ids=["pe:refund"],
                origin=_origin("billing.py"),
            ),
            SemanticPath(
                path_id="path:delete",
                entrypoint="DELETE /account",
                guard_ids=["g:delete"],
                protected_effect_ids=["pe:delete"],
                origin=_origin("accounts.py"),
            ),
        ],
    )


def test_unchanged_semantics_are_reuse_candidates() -> None:
    base = _two_effect_ir()
    head = deepcopy(base)
    head.subject.head_sha = "next"

    plan = plan_incremental_assurance(base, head)

    assert plan.reverify_effects == []
    assert plan.semantic_reuse_candidates == ["pe:delete", "pe:refund"]
    assert plan.new_effects == []
    assert plan.removed_effects == []
    assert plan.changed_semantic_effects == []


def test_local_resource_semantic_change_reverifies_only_one_effect() -> None:
    base = _two_effect_ir()
    head = deepcopy(base)
    invoice = next(
        resource for resource in head.resources if resource.resource_id == "r:invoice"
    )
    invoice.identity_term = ResourceIdentityTerm.symbol("body.invoice_id")

    assert (
        protected_effect_semantic_digest(base, "pe:refund")
        != protected_effect_semantic_digest(head, "pe:refund")
    )
    assert (
        protected_effect_semantic_digest(base, "pe:delete")
        == protected_effect_semantic_digest(head, "pe:delete")
    )

    plan = plan_incremental_assurance(base, head)

    assert plan.reverify_effects == ["pe:refund"]
    assert plan.semantic_reuse_candidates == ["pe:delete"]
    assert plan.changed_semantic_effects == ["pe:refund"]
    assert plan.reverify_reasons["pe:refund"] == ["semantic_slice_changed"]


def test_global_coverage_change_invalidates_all_reuse_candidates() -> None:
    base = _two_effect_ir()
    head = deepcopy(base)
    head.coverage.status = "partial"
    head.coverage.confidence = 0.5
    head.coverage.unsupported_constructs = ["dynamic_dispatch"]

    plan = plan_incremental_assurance(base, head)

    assert plan.reverify_effects == ["pe:delete", "pe:refund"]
    assert plan.semantic_reuse_candidates == []
    assert plan.changed_semantic_effects == ["pe:delete", "pe:refund"]


def test_new_and_removed_effects_are_partitioned_conservatively() -> None:
    base = _two_effect_ir()
    head = deepcopy(base)

    head.protected_effects = [
        effect for effect in head.protected_effects if effect.protected_effect_id != "pe:delete"
    ]
    head.paths = [
        path for path in head.paths if path.path_id != "path:delete"
    ]
    head.guards = [
        guard for guard in head.guards if guard.guard_id != "g:delete"
    ]

    head.effects.append(
        EffectRef(
            effect_id="e:export",
            name="customer.data.export",
            origin=_origin("export.py"),
        )
    )
    head.resources.append(
        ResourceRef(
            resource_id="r:export",
            symbol="export",
            origin=_origin("export.py"),
        )
    )
    head.guards.append(
        AuthorizationGuard(
            guard_id="g:export",
            principal_id="p:user",
            effect_id="e:export",
            resource_id="r:export",
            origin=_origin("export.py"),
        )
    )
    head.protected_effects.append(
        ProtectedEffect(
            protected_effect_id="pe:export",
            principal_id="p:user",
            effect_id="e:export",
            resource_id="r:export",
            origin=_origin("export.py"),
        )
    )
    head.paths.append(
        SemanticPath(
            path_id="path:export",
            entrypoint="POST /export",
            guard_ids=["g:export"],
            protected_effect_ids=["pe:export"],
            origin=_origin("export.py"),
        )
    )

    plan = plan_incremental_assurance(base, head)

    assert plan.new_effects == ["pe:export"]
    assert plan.removed_effects == ["pe:delete"]
    assert plan.reverify_effects == ["pe:export"]
    assert plan.semantic_reuse_candidates == ["pe:refund"]
    assert plan.reverify_reasons["pe:export"] == ["new_protected_effect"]


def test_selective_evaluation_preserves_full_default_and_fails_closed() -> None:
    ir = _two_effect_ir()

    all_results = evaluate_protected_effect_integrity(ir)
    refund_only = evaluate_protected_effect_integrity(
        ir,
        protected_effect_ids=["pe:refund"],
    )

    assert {result.protected_effect_id for result in all_results} == {
        "pe:refund",
        "pe:delete",
    }
    assert [result.protected_effect_id for result in refund_only] == ["pe:refund"]
    assert refund_only[0].status == "pass"

    with pytest.raises(ValueError, match="unknown protected effect ids"):
        evaluate_protected_effect_integrity(
            ir,
            protected_effect_ids=["pe:missing"],
        )


def _workspace_chain(service_source: str) -> AssuranceIR:
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
    materials = AuthMaterials(
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
    profile = FastApiDependencyEffectProfile(
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
    return FastApiDependencyEffectExtractor().compile(materials, profile)


def test_low_level_contract_weakening_forces_reverification() -> None:
    secure_source = """
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

    weakened_source = """
class AgentRepository:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        return agent

class AgentService:
    def __init__(self):
        self._repo = AgentRepository()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._repo.get(agent_id, workspace_id=workspace_id)
""".strip()

    base = _workspace_chain(secure_source)
    head = _workspace_chain(weakened_source)

    plan = plan_incremental_assurance(base, head)

    assert len(base.protected_effects) == 1
    effect_id = base.protected_effects[0].protected_effect_id
    assert effect_id in plan.reverify_effects
    assert effect_id not in plan.semantic_reuse_candidates
    assert effect_id in plan.contract_affected_effects
    assert "contract_dependency_changed" in plan.reverify_reasons[effect_id]
    assert "semantic_slice_changed" in plan.reverify_reasons[effect_id]



def test_incremental_evaluation_runs_only_selected_effects_and_binds_head_digest() -> None:
    base = _two_effect_ir()
    head = deepcopy(base)
    invoice = next(
        resource for resource in head.resources if resource.resource_id == "r:invoice"
    )
    invoice.identity_term = ResourceIdentityTerm.symbol("body.invoice_id")

    plan = plan_incremental_assurance(base, head)
    results = evaluate_incremental_reverification(head, plan)

    assert plan.reverify_effects == ["pe:refund"]
    assert [result.protected_effect_id for result in results] == ["pe:refund"]

    different_head = deepcopy(head)
    different_head.resources[0].identity_term = ResourceIdentityTerm.symbol("other.invoice_id")

    with pytest.raises(ValueError, match="head digest does not match"):
        evaluate_incremental_reverification(different_head, plan)


def test_incremental_evaluation_is_empty_when_all_semantics_are_reusable() -> None:
    base = _two_effect_ir()
    head = deepcopy(base)
    plan = plan_incremental_assurance(base, head)

    assert plan.reverify_effects == []
    assert evaluate_incremental_reverification(head, plan) == []
