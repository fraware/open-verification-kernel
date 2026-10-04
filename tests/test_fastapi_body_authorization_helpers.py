"""Profile-declared body authorization helpers as cut candidates (#post-137).

Composition: source → summary → fragment → IR → obligation → evaluator for
the if-bypass / else-body-helper pattern. Helper names are synthetic profile
keys only; Open WebUI identifiers are not used in generic extractors.
"""

from __future__ import annotations

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    BodyAuthorizationHelperSemantics,
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


_FAIL_CLOSED_HELPER = """
def require_access(user):
    if user is None:
        raise HTTPException(status_code=403)
""".strip()


def _body_helper_profile(
    *,
    with_bypass: bool = False,
    helpers: dict[str, BodyAuthorizationHelperSemantics] | None = None,
) -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        body_authorization_helpers=helpers
        if helpers is not None
        else {
            "require_access": BodyAuthorizationHelperSemantics(
                authorized_effects=("model.invoke",),
                principal_arg=0,
                authorized_resource="chat",
            )
        },
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
    repository_python_files: dict[str, str] | None = None,
    include_repository_python_manifest: bool = True,
):
    # Default: when repo+revision are present, the supplied unit is the complete
    # authenticated Python manifest. Disable the manifest (or pass an explicit
    # subset) to model source_paths-filtered materials without repository closure.
    if repository_python_files is not None:
        closure = repository_python_files
    elif include_repository_python_manifest and repo and head_revision:
        closure = files
    else:
        closure = None
    materials = AuthMaterials(
        base_files=files,
        head_files=files,
        repo=repo,
        base_revision="base",
        head_revision=head_revision,
        repository_python_files=closure,
    )
    return FastApiDependencyEffectExtractor().compile(materials, profile)


def test_profile_body_authorization_helpers_round_trip() -> None:
    payload = {
        "schema_version": "ovk.protected_effect_profile.v1",
        "profile_type": "fastapi_dependency_effects_v1",
        "source_paths": ["app/**/*.py"],
        "sink_effects": {"sink": "model.invoke"},
        "body_authorization_helpers": {
            "require_access": {
                "effects": ["model.invoke"],
                "authorized_resource": "chat",
            },
            "check_access": {
                "effects": ["model.invoke"],
                "authorized_resource": "chat",
            },
        },
        "sink_static_resources": {"sink": "chat"},
        "principal_parameter": "user",
    }
    config = ProtectedEffectProfileConfig.model_validate(payload)
    runtime = config.runtime_profile()
    assert runtime.body_authorization_helpers["require_access"].authorized_effects == (
        "model.invoke",
    )
    assert runtime.body_authorization_helpers["require_access"].authorized_resource == "chat"
    assert "body_authorization_helpers" in config.canonical_payload()


def test_sequential_body_helper_bound_but_unproved_never_pe_pass() -> None:
    """#151: profile binds the helper guard, but reachable-raise stays unproved."""

    source = f"""
from fastapi import Depends, FastAPI, HTTPException
app = FastAPI()

{_FAIL_CLOSED_HELPER}

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    require_access(user)
    return sink(user)
""".strip()
    ir = _compile(
        {"app/routes.py": source},
        profile=_body_helper_profile(),
    )
    assert ir.extractor.extractor_version == "0.61.0"
    assert len(ir.guards) == 1
    assert ir.guards[0].origin.source_range is not None
    assert ir.guards[0].effectiveness == "unproved"
    # Unproved helpers are not cut candidates / do not cover the sink.
    assert ir.authorization_cut_set_evidence == [] or all(
        not cut.covers_all_paths or cut.guard_ids == []
        for cut in ir.authorization_cut_set_evidence
    )
    evaluation = evaluate_protected_effect_integrity(ir)
    assert len(evaluation) == 1
    assert evaluation[0].status != "pass"


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
        profile=_body_helper_profile(
            helpers={
                "require_access": BodyAuthorizationHelperSemantics(
                    authorized_effects=("model.invoke",),
                    principal_arg=0,
                    authorized_resource="chat",
                )
            }
        ),
    )
    assert ir.guards == []
    assert ir.authorization_cut_set_evidence == []
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"


def test_bypass_else_body_helper_cannot_compose_while_helper_unproved() -> None:
    """#151: proved bypass edge alone cannot compose with an unproved helper."""

    files = {
        "app/middleware.py": """
def attach(request):
    request.state.bypass_filter = True
""".strip(),
        "app/helpers.py": _FAIL_CLOSED_HELPER,
        "app/routes.py": """
from fastapi import Depends, FastAPI, HTTPException
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
    assert all(
        guard.effectiveness != "established"
        for guard in ir.guards
        if "body_auth" in guard.guard_id
    )
    # Bypass may still be established; body helper is not a cut member.
    assert any(
        item.status == "established" and item.control_point_edge_id is not None
        for item in ir.bypass_authority_evidence
    )
    if ir.authorization_cut_set_evidence:
        cut = ir.authorization_cut_set_evidence[0]
        assert cut.covers_all_paths is False or not cut.node_control_points
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"


def test_body_helper_alone_does_not_cover_bypass_true_branch() -> None:
    """Near-miss: unproved body helper without proved bypass leaves branch open."""

    source = f"""
from fastapi import Depends, FastAPI, HTTPException
app = FastAPI()

{_FAIL_CLOSED_HELPER}

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
    assert all(guard.effectiveness != "established" for guard in ir.guards)
    if ir.authorization_cut_set_evidence:
        cut = ir.authorization_cut_set_evidence[0]
        assert cut.covers_all_paths is False
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"


def test_sparse_workspace_closure_refuses_bypass_collective_pass() -> None:
    """Adversarial: workspace/sparse materials must not false-PASS via bypass."""

    files = {
        "app/middleware.py": """
def attach(request):
    request.state.bypass_filter = True
""".strip(),
        "app/helpers.py": _FAIL_CLOSED_HELPER,
        "app/routes.py": """
from fastapi import Depends, FastAPI, HTTPException
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
    assert all(guard.effectiveness != "established" for guard in ir.guards)
    if ir.authorization_cut_set_evidence:
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
