"""FastAPI binding of structural authorization cut-set evidence."""

from __future__ import annotations

from ovk.compilers.authorization.authorization_cut_set import (
    build_authorization_cut_set_evidence,
)
from ovk.compilers.authorization.handler_control_flow import (
    build_handler_control_flow_from_source,
)
from ovk.compilers.authorization.incremental_fastapi_compiler import (
    compile_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.persistent_fastapi_state import (
    PersistentFastApiIncrementalStateCache,
    compile_persistent_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
    ResourceOwnershipAssertionSemantics,
)
from ovk.compilers.authorization.python_ast_index import parse_head_python_materials
from ovk.compilers.authorization.fastapi_route_summary import build_route_summary_index
from ovk.compilers.authorization.resource_return_contracts import (
    build_contract_summary_index,
)
from ovk.compilers.authorization.semantic_summary_cache import (
    PersistentPythonSemanticSummaryCache,
)
from ovk.core.assurance_ir import (
    AuthorizationGuard,
    ProtectedEffect,
    SemanticOrigin,
)
from ovk.core.models import SourceRange


def _origin(path: str, line: int) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="test",
        extractor_version="0.1.0",
        source_range=SourceRange(
            path=path,
            start_line=line,
            end_line=line,
        ),
    )


def _ownership_profile() -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects={"_prepare_run": "thread.run.create"},
        sink_identity_args={"_prepare_run": 1},
        ownership_assertions={
            "session.scalar": ResourceOwnershipAssertionSemantics(
                resource_identity_attribute="thread_id",
                owner_attribute="user_id",
                principal_attribute="identity",
                authorized_effects=("thread.run.create",),
                allow_missing_resource=True,
                truthy_when_present=False,
            )
        },
        principal_parameter="user",
    )


def _compile(source: str, *, profile: FastApiDependencyEffectProfile | None = None):
    materials = AuthMaterials(
        base_files={"api/runs.py": source},
        head_files={"api/runs.py": source},
        repo="example/cut-set",
        base_revision="base",
        head_revision="head",
    )
    return FastApiDependencyEffectExtractor().compile(
        materials,
        profile or _ownership_profile(),
    )


def _guard(guard_id: str, path: str, line: int) -> AuthorizationGuard:
    return AuthorizationGuard(
        guard_id=guard_id,
        principal_id="principal:user",
        effect_id="effect:sink",
        resource_id="resource:item",
        origin=_origin(path, line),
    )


def _effect(path: str, line: int) -> ProtectedEffect:
    return ProtectedEffect(
        protected_effect_id="protected:sink",
        principal_id="principal:user",
        effect_id="effect:sink",
        resource_id="resource:item",
        origin=_origin(path, line),
    )


def test_sequential_body_guard_singleton_cut_covers_sink() -> None:
    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/threads/{thread_id}/runs")
async def create_run(
    thread_id: str,
    request,
    user = Depends(get_current_user),
    session = Depends(get_session),
):
    existing_thread = await session.scalar(
        select(ThreadORM).where(ThreadORM.thread_id == thread_id)
    )
    if existing_thread is not None and existing_thread.user_id != user.identity:
        raise HTTPException(404, "Thread not found")
    return await _prepare_run(session, thread_id, request, user)
""".strip()

    ir = _compile(source)
    assert ir.extractor.extractor_version == "0.22.0"
    assert len(ir.authorization_cut_set_evidence) == 1
    evidence = ir.authorization_cut_set_evidence[0]
    assert evidence.covers_all_paths is True
    assert evidence.coverage_status == "complete"
    assert evidence.unresolved_guard_ids == []
    assert len(evidence.guard_ids) == 1
    assert evidence.node_control_points == []
    assert len(evidence.edge_control_points) == 1
    assert evidence.reason == (
        "authorization_control_points_disconnect_entry_from_sink"
    )


def test_both_branch_body_guards_cover_sink() -> None:
    path = "handler.py"
    source = """
def handler(user, flag):
    if flag:
        require_access(user)
    else:
        require_access(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path=path)
    guards = [
        _guard("guard:a", path, 3),
        _guard("guard:b", path, 5),
    ]
    evidence = build_authorization_cut_set_evidence(
        effect=_effect(path, 6),
        entrypoint="POST /demo",
        cfg=cfg,
        candidate_guards=guards,
        origin=_origin(path, 1),
    )
    assert evidence is not None
    assert evidence.covers_all_paths is True
    assert evidence.coverage_status == "complete"
    assert set(evidence.guard_ids) == {"guard:a", "guard:b"}
    assert evidence.unresolved_guard_ids == []


def test_multi_outcome_branch_guard_binding_is_unknown() -> None:
    """A guard bound to a branch with two sink-reaching arms cannot authorize."""

    path = "handler.py"
    source = """
def handler(flag, user):
    if flag:
        observe_a(user)
    else:
        observe_b(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path=path)
    evidence = build_authorization_cut_set_evidence(
        effect=_effect(path, 6),
        entrypoint="POST /demo",
        cfg=cfg,
        candidate_guards=[_guard("guard:branch", path, 2)],
        origin=_origin(path, 1),
    )
    assert evidence is not None
    assert evidence.coverage_status == "unknown"
    assert evidence.covers_all_paths is False
    assert evidence.reason == "branch_outcome_control_point_ambiguous"
    assert evidence.unresolved_guard_ids == ["guard:branch"]


def test_only_one_branch_guard_emits_complete_uncovered_path() -> None:
    path = "handler.py"
    source = """
def handler(user, flag):
    if flag:
        require_access(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path=path)
    evidence = build_authorization_cut_set_evidence(
        effect=_effect(path, 4),
        entrypoint="POST /demo",
        cfg=cfg,
        candidate_guards=[_guard("guard:a", path, 3)],
        origin=_origin(path, 1),
    )
    assert evidence is not None
    assert evidence.covers_all_paths is False
    assert evidence.coverage_status == "complete"
    assert evidence.uncovered_path_node_ids
    assert evidence.uncovered_path_node_ids[0] == cfg.entry_id
    assert evidence.uncovered_path_node_ids[-1] == evidence.effect_cfg_node_id


def test_ambiguous_guard_binding_is_unknown_never_complete_uncovered() -> None:
    path = "handler.py"
    source = """
def handler(user):
    require_access(user); other(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path=path)
    evidence = build_authorization_cut_set_evidence(
        effect=_effect(path, 3),
        entrypoint="POST /demo",
        cfg=cfg,
        candidate_guards=[
            _guard("guard:a", path, 2),
            _guard("guard:b", path, 2),
        ],
        origin=_origin(path, 1),
    )
    assert evidence is not None
    assert evidence.coverage_status == "unknown"
    assert evidence.covers_all_paths is False
    assert evidence.uncovered_path_node_ids == []
    assert set(evidence.unresolved_guard_ids) == {"guard:a", "guard:b"}


def test_partial_cfg_before_sink_is_partial() -> None:
    path = "handler.py"
    source = """
def handler(user):
    for item in items:
        require_access(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path=path)
    assert cfg.coverage_status == "partial"
    evidence = build_authorization_cut_set_evidence(
        effect=_effect(path, 4),
        entrypoint="POST /demo",
        cfg=cfg,
        candidate_guards=[_guard("guard:a", path, 2)],
        origin=_origin(path, 1),
    )
    assert evidence is not None
    assert evidence.coverage_status == "partial"
    assert evidence.covers_all_paths is False
    assert evidence.uncovered_path_node_ids == []


def test_ambiguous_sink_binding_is_unknown() -> None:
    path = "handler.py"
    source = """
def handler(user):
    require_access(user)
    sink(user); other(user)
    return None
""".strip()
    cfg = build_handler_control_flow_from_source(source, path=path)
    evidence = build_authorization_cut_set_evidence(
        effect=_effect(path, 3),
        entrypoint="POST /demo",
        cfg=cfg,
        candidate_guards=[_guard("guard:a", path, 2)],
        origin=_origin(path, 1),
    )
    assert evidence is not None
    assert evidence.coverage_status == "unknown"
    assert evidence.covers_all_paths is False
    assert evidence.effect_cfg_node_id is None
    assert evidence.reason == "sink_cfg_binding_unresolved"
    assert evidence.unresolved_guard_ids == ["guard:a"]


def test_entrypoint_dependency_excluded_from_body_cut_set() -> None:
    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/threads/{thread_id}/runs")
async def create_run(
    thread_id: str,
    request,
    user = Depends(get_current_user),
    session = Depends(get_session),
):
    existing_thread = await session.scalar(
        select(ThreadORM).where(ThreadORM.thread_id == thread_id)
    )
    if existing_thread is not None and existing_thread.user_id != user.identity:
        raise HTTPException(404, "Thread not found")
    return await _prepare_run(session, thread_id, request, user)
""".strip()
    profile = FastApiDependencyEffectProfile(
        sink_effects={"_prepare_run": "thread.run.create"},
        sink_identity_args={"_prepare_run": 1},
        ownership_assertions={
            "session.scalar": ResourceOwnershipAssertionSemantics(
                resource_identity_attribute="thread_id",
                owner_attribute="user_id",
                principal_attribute="identity",
                authorized_effects=("thread.run.create",),
                allow_missing_resource=True,
                truthy_when_present=False,
            )
        },
        dependency_guard_resources={"get_current_user": "user_identity"},
        dependency_guard_effects={
            "get_current_user": ("thread.run.create",),
        },
        principal_parameter="user",
    )
    ir = _compile(source, profile=profile)
    assert ir.authorization_cut_set_evidence
    evidence = ir.authorization_cut_set_evidence[0]
    path_guards = set(ir.paths[0].guard_ids)
    assert len(path_guards) >= 2
    assert set(evidence.guard_ids) <= path_guards
    assert len(evidence.guard_ids) == 1
    assert evidence.covers_all_paths is True


def test_route_dependency_excluded_from_cut_set_guard_ids() -> None:
    source = """
from fastapi import APIRouter, Depends

router = APIRouter(dependencies=[Depends(require_auth)])

@router.post("/threads/{thread_id}/runs")
async def create_run(
    thread_id: str,
    request,
    user = Depends(get_current_user),
    session = Depends(get_session),
):
    existing_thread = await session.scalar(
        select(ThreadORM).where(ThreadORM.thread_id == thread_id)
    )
    if existing_thread is not None and existing_thread.user_id != user.identity:
        raise HTTPException(404, "Thread not found")
    return await _prepare_run(session, thread_id, request, user)
""".strip()
    profile = FastApiDependencyEffectProfile(
        sink_effects={"_prepare_run": "thread.run.create"},
        sink_identity_args={"_prepare_run": 1},
        ownership_assertions={
            "session.scalar": ResourceOwnershipAssertionSemantics(
                resource_identity_attribute="thread_id",
                owner_attribute="user_id",
                principal_attribute="identity",
                authorized_effects=("thread.run.create",),
                allow_missing_resource=True,
                truthy_when_present=False,
            )
        },
        route_dependency_guard_resources={"require_auth": "mcp_transport"},
        route_dependency_guard_effects={
            "require_auth": ("thread.run.create",),
        },
        principal_parameter="user",
    )
    ir = _compile(source, profile=profile)
    assert ir.authorization_cut_set_evidence
    evidence = ir.authorization_cut_set_evidence[0]
    assert len(evidence.guard_ids) == 1
    body_guard = evidence.guard_ids[0]
    assert body_guard in ir.paths[0].guard_ids
    route_guards = [
        guard.guard_id
        for guard in ir.guards
        if guard.guard_id != body_guard
    ]
    assert route_guards
    assert set(evidence.guard_ids).isdisjoint(route_guards)


def test_depends_only_handler_emits_no_body_cut_evidence() -> None:
    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/threads/{thread_id}/runs")
async def create_run(
    thread_id: str,
    request,
    user = Depends(get_current_user),
):
    return await _prepare_run(session, thread_id, request, user)
""".strip()
    profile = FastApiDependencyEffectProfile(
        sink_effects={"_prepare_run": "thread.run.create"},
        sink_identity_args={"_prepare_run": 1},
        dependency_guard_resources={"get_current_user": "user_identity"},
        dependency_guard_effects={
            "get_current_user": ("thread.run.create",),
        },
        principal_parameter="user",
    )
    ir = _compile(source, profile=profile)
    assert ir.guards
    assert ir.authorization_cut_set_evidence == []
    assert "authorization_cut_set_evidence" not in ir.canonical_payload()


def test_empty_cut_set_collection_preserves_additive_identity() -> None:
    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/health")
async def health():
    return {"ok": True}
""".strip()
    ir = _compile(
        source,
        profile=FastApiDependencyEffectProfile(sink_effects={}),
    )
    assert ir.authorization_cut_set_evidence == []
    assert "authorization_cut_set_evidence" not in ir.canonical_payload()


def test_branch_structure_change_changes_cut_set_digest() -> None:
    covered = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/threads/{thread_id}/runs")
async def create_run(
    thread_id: str,
    request,
    user = Depends(get_current_user),
    session = Depends(get_session),
):
    existing_thread = await session.scalar(
        select(ThreadORM).where(ThreadORM.thread_id == thread_id)
    )
    if existing_thread is not None and existing_thread.user_id != user.identity:
        raise HTTPException(404, "Thread not found")
    return await _prepare_run(session, thread_id, request, user)
""".strip()
    branched = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/threads/{thread_id}/runs")
async def create_run(
    thread_id: str,
    request,
    user = Depends(get_current_user),
    session = Depends(get_session),
    flag: bool = False,
):
    if flag:
        marker = True
    existing_thread = await session.scalar(
        select(ThreadORM).where(ThreadORM.thread_id == thread_id)
    )
    if existing_thread is not None and existing_thread.user_id != user.identity:
        raise HTTPException(404, "Thread not found")
    return await _prepare_run(session, thread_id, request, user)
""".strip()
    covered_ir = _compile(covered)
    branched_ir = _compile(branched)
    assert covered_ir.assurance_ir_digest != branched_ir.assurance_ir_digest
    assert (
        covered_ir.authorization_cut_set_evidence[0].control_flow_summary_digest
        != branched_ir.authorization_cut_set_evidence[0].control_flow_summary_digest
    )
    assert covered_ir.authorization_cut_set_evidence[0].covers_all_paths is True
    assert branched_ir.authorization_cut_set_evidence[0].covers_all_paths is True


def test_incremental_matches_full_canonical_ir_with_cut_set() -> None:
    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/threads/{thread_id}/runs")
async def create_run(
    thread_id: str,
    request,
    user = Depends(get_current_user),
    session = Depends(get_session),
):
    existing_thread = await session.scalar(
        select(ThreadORM).where(ThreadORM.thread_id == thread_id)
    )
    if existing_thread is not None and existing_thread.user_id != user.identity:
        raise HTTPException(404, "Thread not found")
    return await _prepare_run(session, thread_id, request, user)
""".strip()
    materials = AuthMaterials(
        base_files={"api/runs.py": source},
        head_files={"api/runs.py": source},
        repo="example/cut-set-incremental",
        base_revision="base",
        head_revision="head",
    )
    profile = _ownership_profile()
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
    incremental = compile_incremental_fastapi_assurance(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes,
    )
    full = FastApiDependencyEffectExtractor().compile(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes,
    )
    assert incremental.ir.canonical_payload() == full.canonical_payload()
    assert incremental.ir.authorization_cut_set_evidence
    assert full.authorization_cut_set_evidence


def test_persistent_round_trip_preserves_cut_set_evidence(tmp_path) -> None:
    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/threads/{thread_id}/runs")
async def create_run(
    thread_id: str,
    request,
    user = Depends(get_current_user),
    session = Depends(get_session),
):
    existing_thread = await session.scalar(
        select(ThreadORM).where(ThreadORM.thread_id == thread_id)
    )
    if existing_thread is not None and existing_thread.user_id != user.identity:
        raise HTTPException(404, "Thread not found")
    return await _prepare_run(session, thread_id, request, user)
""".strip()
    materials = AuthMaterials(
        base_files={"api/runs.py": source},
        head_files={"api/runs.py": source},
        repo="example/cut-set-persistent",
        base_revision="base",
        head_revision="head-1",
    )
    profile = _ownership_profile()
    first = compile_persistent_incremental_fastapi_assurance(
        materials,
        profile,
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            tmp_path / "summaries"
        ),
        state_cache=PersistentFastApiIncrementalStateCache(tmp_path / "state"),
    )
    assert first.compilation.ir.authorization_cut_set_evidence
    first_payload = first.compilation.ir.canonical_payload()

    second = compile_persistent_incremental_fastapi_assurance(
        materials,
        profile,
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            tmp_path / "summaries"
        ),
        state_cache=PersistentFastApiIncrementalStateCache(tmp_path / "state"),
    )
    assert second.previous_state_loaded is True
    assert second.compilation.ir.canonical_payload() == first_payload
    assert second.compilation.ir.authorization_cut_set_evidence
