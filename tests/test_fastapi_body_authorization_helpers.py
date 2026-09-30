"""Profile-declared body authorization helpers as cut candidates (#post-137).

Composition: source → summary → fragment → IR → obligation → evaluator for
the if-bypass / else-body-helper pattern. Helper names are synthetic profile
keys only; Open WebUI identifiers are not used in generic extractors.
"""

from __future__ import annotations

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
from ovk.core.protected_effect_profile import ProtectedEffectProfileConfig


def _origin(line: int) -> SemanticOrigin:
    return SemanticOrigin(
        path="app/routes.py",
        extractor_id="test",
        extractor_version="0.1.0",
        source_range=SourceRange(
            path="app/routes.py",
            start_line=line,
            end_line=line,
        ),
    )


def _body_helper_profile(
    *,
    with_bypass: bool = False,
    helpers: dict[str, tuple[str, ...]] | None = None,
) -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        body_authorization_helpers=helpers
        if helpers is not None
        else {"require_access": ("model.invoke",)},
        trusted_bypass_authorities=(
            {"request.state.bypass_filter": ("model.invoke",)}
            if with_bypass
            else {}
        ),
        principal_parameter="user",
    )


def _compile(
    files: dict[str, str],
    *,
    profile: FastApiDependencyEffectProfile,
    repo: str | None = "example/body-auth",
    head_revision: str | None = "rev1",
):
    materials = AuthMaterials(
        base_files=files,
        head_files=files,
        repo=repo,
        base_revision="base",
        head_revision=head_revision,
    )
    return FastApiDependencyEffectExtractor().compile(materials, profile)


def test_profile_body_authorization_helpers_round_trip() -> None:
    payload = {
        "schema_version": "ovk.protected_effect_profile.v1",
        "profile_type": "fastapi_dependency_effects_v1",
        "source_paths": ["app/**/*.py"],
        "sink_effects": {"sink": "model.invoke"},
        "body_authorization_helpers": {
            "require_access": {"effects": ["model.invoke"]},
            "check_access": {"effects": ["model.invoke"]},
        },
        "principal_parameter": "user",
    }
    config = ProtectedEffectProfileConfig.model_validate(payload)
    runtime = config.runtime_profile()
    assert runtime.body_authorization_helpers == {
        "require_access": ("model.invoke",),
        "check_access": ("model.invoke",),
    }
    assert "body_authorization_helpers" in config.canonical_payload()


def test_sequential_body_helper_is_cut_candidate_and_pe_pass() -> None:
    """Positive: profile-declared sequential body helper covers sink."""

    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    require_access(user)
    return sink(user)
""".strip()
    ir = _compile(
        {"app/routes.py": source},
        profile=_body_helper_profile(),
    )
    assert ir.extractor.extractor_version == "0.23.0"
    assert len(ir.guards) == 1
    assert ir.guards[0].origin.source_range is not None
    assert len(ir.authorization_cut_set_evidence) == 1
    cut = ir.authorization_cut_set_evidence[0]
    assert cut.covers_all_paths is True
    assert cut.coverage_status == "complete"
    assert cut.guard_ids == [ir.guards[0].guard_id]
    assert cut.node_control_points
    evaluation = evaluate_protected_effect_integrity(ir)
    assert len(evaluation) == 1
    assert evaluation[0].status == "pass"


def test_near_miss_helper_outside_profile_stays_unknown() -> None:
    """Near-miss: English-looking helper absent from profile never authorizes."""

    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    check_access(user)
    return sink(user)
""".strip()
    ir = _compile(
        {"app/routes.py": source},
        profile=_body_helper_profile(helpers={"require_access": ("model.invoke",)}),
    )
    assert ir.guards == []
    assert ir.authorization_cut_set_evidence == []
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"


def test_bypass_else_body_helper_compose_cut_node_and_edge() -> None:
    """Composition: proved bypass edge + body helper jointly cover sink."""

    files = {
        "app/middleware.py": """
def attach(request):
    request.state.bypass_filter = True
""".strip(),
        "app/routes.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    if request.state.bypass_filter:
        pass
    else:
        require_access(user)
    return sink(user)
""".strip(),
    }
    ir = _compile(
        files,
        profile=_body_helper_profile(with_bypass=True),
        repo="example/body-auth",
        head_revision="rev1",
    )
    assert len(ir.authorization_cut_set_evidence) == 1
    cut = ir.authorization_cut_set_evidence[0]
    body_guards = [
        guard
        for guard in ir.guards
        if "body_auth" in guard.guard_id or guard.guard_id in cut.guard_ids
    ]
    assert len(cut.guard_ids) == 1
    assert cut.guard_ids[0] in {guard.guard_id for guard in body_guards}
    assert cut.node_control_points
    assert cut.edge_control_points
    assert cut.covers_all_paths is True
    assert cut.coverage_status == "complete"
    assert any(
        item.status == "established" and item.control_point_edge_id is not None
        for item in ir.bypass_authority_evidence
    )
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status == "pass"


def test_body_helper_alone_does_not_cover_bypass_true_branch() -> None:
    """Near-miss: body helper without proved bypass leaves true branch open."""

    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    if request.state.bypass_filter:
        pass
    else:
        require_access(user)
    return sink(user)
""".strip()
    ir = _compile(
        {"app/routes.py": source},
        profile=_body_helper_profile(with_bypass=False),
    )
    cut = ir.authorization_cut_set_evidence[0]
    assert cut.covers_all_paths is False
    assert cut.coverage_status == "complete"
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"


def test_sparse_workspace_closure_refuses_bypass_collective_pass() -> None:
    """Adversarial: workspace/sparse materials must not false-PASS via bypass."""

    files = {
        "app/middleware.py": """
def attach(request):
    request.state.bypass_filter = True
""".strip(),
        "app/routes.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    if request.state.bypass_filter:
        pass
    else:
        require_access(user)
    return sink(user)
""".strip(),
    }
    ir = _compile(
        files,
        profile=_body_helper_profile(with_bypass=True),
        repo=None,
        head_revision=None,
    )
    assert all(item.status != "established" for item in ir.bypass_authority_evidence)
    cut = ir.authorization_cut_set_evidence[0]
    # Without established bypass edge merge, body helper alone cannot cover.
    assert cut.covers_all_paths is False or not cut.edge_control_points
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"


def test_collective_cut_refuses_unproved_bypass_claimed_edge() -> None:
    """PE: bypass-claimed cut edges without established proof refuse the cut."""

    from tests.test_protected_effect_integrity import _base_ir, _status

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
            origin=_origin(9),
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
            origin=_origin(9),
        )
    ]
    ir.bypass_authority_evidence = [
        BypassAuthorityEvidence(
            evidence_id="bypass:filter",
            field_name="bypass_filter",
            read_expression="request.state.bypass_filter",
            read_origin=_origin(2),
            status="unknown",
            control_point_edge_id=edge_id,
            writer_evidence_ids=[],
            closed_world_scope_digest=None,
            reason="sparse_or_workspace_scope_not_repo_closure",
            origin=_origin(2),
        )
    ]
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
            reason="authorization_control_points_disconnect_entry_from_sink",
            origin=_origin(4),
        )
    ]

    obligation = compile_protected_effect_integrity(ir)[0]
    assert _status(obligation, "guard_presence") == "violated"
    assert obligation.path_candidate_guard_ids["path:refund"] == []
