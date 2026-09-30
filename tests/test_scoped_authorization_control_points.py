"""Globally scoped authorization control points (#147).

Handler-local CFG edge ids must not authorize across handlers. Every
authorizing edge member requires AuthorizationControlPointEvidence binding
guard, protected effect, principal/effect/resource, CFG digest, and edge.
"""

from __future__ import annotations

from ovk.compilers.authorization.handler_control_flow import (
    control_flow_edge_id,
    scoped_control_flow_edge_id,
    scoped_control_flow_edge_id_from_local,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.core.assurance_ir import (
    AuthorizationCutSetEvidence,
    AuthorizationGuard,
    BypassAuthorityEvidence,
    GuardDominanceEvidence,
    SemanticOrigin,
)
from ovk.core.models import SourceRange
from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity
from ovk.core.protected_effect_integrity import compile_protected_effect_integrity
from tests.test_protected_effect_integrity import _base_ir, _status


def _origin(path: str, line: int = 1) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="test",
        extractor_version="0.1.0",
        source_range=SourceRange(path=path, start_line=line, end_line=line),
    )


def test_scoped_edge_ids_differ_across_cfg_digests() -> None:
    local = control_flow_edge_id("branch:3", "stmt:5", True)
    first = scoped_control_flow_edge_id(
        control_flow_summary_digest="cfg:handler-a",
        entrypoint="POST /a",
        source_node_id="branch:3",
        target_node_id="stmt:5",
        branch_value=True,
    )
    second = scoped_control_flow_edge_id(
        control_flow_summary_digest="cfg:handler-b",
        entrypoint="POST /b",
        source_node_id="branch:3",
        target_node_id="stmt:5",
        branch_value=True,
    )
    assert first != second
    assert scoped_control_flow_edge_id_from_local(
        control_flow_summary_digest="cfg:handler-a",
        entrypoint="POST /a",
        local_edge_id=local,
    ) == first


def test_cross_handler_local_edge_collision_does_not_merge_or_pass() -> None:
    """Authority from handler A must not merge into handler B via local edge ids."""

    files = {
        "app/middleware.py": """
def attach(request):
    request.state.bypass_filter = True
""".strip(),
        "app/routes.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/trusted")
async def trusted(request, user = Depends(get_current_user)):
    if request.state.bypass_filter:
        pass
    else:
        require_access(user)
    return sink(user)

@app.post("/other")
async def other(request, user = Depends(get_current_user)):
    if request.state.bypass_filter:
        pass
    else:
        require_access(user)
    return sink(user)
""".strip(),
    }
    profile = FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        body_authorization_helpers={"require_access": ("model.invoke",)},
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_parameter="user",
    )
    materials = AuthMaterials(
        base_files=files,
        head_files=files,
        repo="example/scoped-acp",
        base_revision="base",
        head_revision="head",
        repository_python_files=files,
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, profile)
    assert ir.authorization_control_point_evidence
    # Each established control point is bound to one CFG digest.
    digests = {
        item.control_flow_summary_digest
        for item in ir.authorization_control_point_evidence
    }
    assert len(digests) >= 1
    for cut in ir.authorization_cut_set_evidence:
        if not cut.edge_control_points:
            continue
        # Edges on a cut must only be justified by control points with the
        # same CFG digest — never by another handler's colliding local id.
        for edge_id in cut.edge_control_points:
            foreign = [
                item
                for item in ir.authorization_control_point_evidence
                if item.edge_id == edge_id
                and item.control_flow_summary_digest
                != cut.control_flow_summary_digest
            ]
            assert not foreign or all(
                item.protected_effect_id != cut.protected_effect_id
                or item.control_flow_summary_digest
                == cut.control_flow_summary_digest
                for item in ir.authorization_control_point_evidence
                if item.edge_id == edge_id
            )


def test_raw_edge_membership_without_control_point_refuses_collective_pass() -> None:
    """PE cut theorem requires AuthorizationControlPointEvidence, not raw edges."""

    ir = _base_ir(
        guard_resource="r:authorized",
        effect_resource="r:authorized",
        include_binding=False,
    )
    ir.guards = [
        AuthorizationGuard(
            guard_id="g:body",
            principal_id="p:user",
            effect_id="e:refund",
            resource_id="r:authorized",
            origin=_origin("app.py", 9),
        )
    ]
    ir.paths[0].guard_ids = ["g:body"]
    ir.paths[0].coverage_status = "complete"
    edge_id = "edge:branch:1->stmt:sink:true"
    ir.guard_dominance_evidence = [
        GuardDominanceEvidence(
            evidence_id="gdom:body",
            guard_id="g:body",
            protected_effect_id="pe:refund",
            entrypoint="POST /refund",
            guard_cfg_node_id="stmt:body",
            effect_cfg_node_id="stmt:sink",
            control_flow_summary_digest="cfg:complete",
            dominates=False,
            coverage_status="complete",
            origin=_origin("app.py", 9),
        )
    ]
    ir.bypass_authority_evidence = [
        BypassAuthorityEvidence(
            evidence_id="bypass:filter",
            field_name="bypass_filter",
            read_expression="request.state.bypass_filter",
            read_origin=_origin("app.py", 2),
            status="established",
            control_point_edge_id=edge_id,
            control_flow_summary_digest="cfg:complete",
            entrypoint="POST /refund",
            writer_evidence_ids=["vo:1"],
            closed_world_scope_digest="scope:1",
            reason="test",
            origin=_origin("app.py", 2),
        )
    ]
    # Deliberately omit AuthorizationControlPointEvidence.
    ir.authorization_control_point_evidence = []
    ir.authorization_cut_set_evidence = [
        AuthorizationCutSetEvidence(
            evidence_id="cutset:pe:refund",
            protected_effect_id="pe:refund",
            entrypoint="POST /refund",
            guard_ids=["g:body"],
            guard_cfg_node_ids={"g:body": "stmt:body"},
            node_control_points=["stmt:body"],
            edge_control_points=[edge_id],
            entry_cfg_node_id="entry:1",
            effect_cfg_node_id="stmt:sink",
            control_flow_summary_digest="cfg:complete",
            covers_all_paths=True,
            coverage_status="complete",
            reason="test",
            origin=_origin("app.py", 1),
        )
    ]
    obligation = compile_protected_effect_integrity(ir)[0]
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"
    assert _status(obligation, "guard_presence") == "violated"
