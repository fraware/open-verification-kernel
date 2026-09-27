from __future__ import annotations

from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
    ResourceOwnershipAssertionSemantics,
)
from ovk.core.protected_effect_evaluation import (
    evaluate_protected_effect_integrity,
)


SECURE_TRUTHY = """
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
    if existing_thread and existing_thread.user_id != user.identity:
        raise HTTPException(404, "Thread not found")
    return await _prepare_run(session, thread_id, request, user)
""".strip()


SECURE_EXPLICIT = """
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


VULNERABLE = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/threads/{thread_id}/runs")
async def create_run(
    thread_id: str,
    request,
    user = Depends(get_current_user),
    session = Depends(get_session),
):
    return await _prepare_run(session, thread_id, request, user)
""".strip()


def _profile(*, truthy_when_present: bool) -> FastApiDependencyEffectProfile:
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
                truthy_when_present=truthy_when_present,
            )
        },
        principal_parameter="user",
    )


def _evaluate(source: str, *, truthy_when_present: bool):
    materials = materials_from_pair(
        path="api/runs.py",
        base_source=source,
        head_source=source,
        repo="example/ownership",
        base_revision="base",
        head_revision="head",
    )
    ir = FastApiDependencyEffectExtractor().compile(
        materials,
        _profile(truthy_when_present=truthy_when_present),
    )
    result = evaluate_protected_effect_integrity(ir)[0]
    return ir, result


def test_truthy_fail_closed_ownership_assertion_establishes_guard_when_declared() -> None:
    ir, result = _evaluate(SECURE_TRUTHY, truthy_when_present=True)

    assert ir.coverage.status == "complete"
    assert len(ir.protected_effects) == 1
    assert len(ir.guards) == 1
    assert ir.guards[0].resource_id == ir.protected_effects[0].resource_id
    assert ir.guards[0].principal_id == ir.protected_effects[0].principal_id
    assert result.status == "pass"


def test_missing_ownership_assertion_refutes_protected_effect_integrity() -> None:
    ir, result = _evaluate(VULNERABLE, truthy_when_present=True)

    assert ir.coverage.status == "complete"
    assert len(ir.guards) == 0
    assert result.status == "fail"
    guard = next(
        item for item in result.checks if item.dimension == "guard_presence"
    )
    assert guard.status == "violated"


def test_truthy_source_form_requires_explicit_profile_assumption() -> None:
    ir, result = _evaluate(SECURE_TRUTHY, truthy_when_present=False)

    assert ir.coverage.status == "partial"
    assert any(
        "ownership_assertion_truthiness_unproved" in item
        for item in ir.coverage.unsupported_constructs
    )
    assert result.status != "pass"


def test_explicit_is_not_none_form_needs_no_truthiness_assumption() -> None:
    ir, result = _evaluate(SECURE_EXPLICIT, truthy_when_present=False)

    assert ir.coverage.status == "complete"
    assert len(ir.guards) == 1
    assert result.status == "pass"


def test_wrong_owner_attribute_does_not_silently_authorize() -> None:
    source = SECURE_EXPLICIT.replace(
        "existing_thread.user_id",
        "existing_thread.team_id",
    )
    ir, result = _evaluate(source, truthy_when_present=False)

    assert len(ir.guards) == 0
    assert result.status != "pass"


def test_ownership_assertion_must_precede_protected_effect() -> None:
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
    result = await _prepare_run(session, thread_id, request, user)
    existing_thread = await session.scalar(
        select(ThreadORM).where(ThreadORM.thread_id == thread_id)
    )
    if existing_thread is not None and existing_thread.user_id != user.identity:
        raise HTTPException(404, "Thread not found")
    return result
""".strip()

    ir, result = _evaluate(source, truthy_when_present=False)

    assert len(ir.guards) == 0
    assert result.status != "pass"


SECURE_ASYNC_WITH = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/threads/{thread_id}/runs/wait")
async def wait_for_run(
    thread_id: str,
    request,
    user = Depends(get_current_user),
):
    maker = get_session_maker()
    async with maker() as session:
        existing_thread = await session.scalar(
            select(ThreadORM).where(ThreadORM.thread_id == thread_id)
        )
        if existing_thread and existing_thread.user_id != user.identity:
            raise HTTPException(404, "Thread not found")
        return await _prepare_run(session, thread_id, request, user)
""".strip()


def test_ownership_assertion_and_sink_inside_same_async_with_block_pass() -> None:
    ir, result = _evaluate(
        SECURE_ASYNC_WITH,
        truthy_when_present=True,
    )

    assert ir.coverage.status == "complete"
    assert len(ir.guards) == 1
    assert result.status == "pass"
    assert ir.paths[0].coverage_status == "complete"


def test_ownership_guard_does_not_cross_into_async_with_sink_scope() -> None:
    source = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/threads/{thread_id}/runs/wait")
async def wait_for_run(
    thread_id: str,
    request,
    user = Depends(get_current_user),
    session = Depends(get_session),
):
    existing_thread = await session.scalar(
        select(ThreadORM).where(ThreadORM.thread_id == thread_id)
    )
    if existing_thread and existing_thread.user_id != user.identity:
        raise HTTPException(404, "Thread not found")
    maker = get_session_maker()
    async with maker() as inner_session:
        return await _prepare_run(inner_session, thread_id, request, user)
""".strip()

    ir, result = _evaluate(source, truthy_when_present=True)

    assert len(ir.protected_effects) == 1
    assert len(ir.guards) == 0
    assert result.status == "fail"


def test_unrelated_branch_inside_async_with_keeps_local_coverage_partial() -> None:
    source = SECURE_ASYNC_WITH.replace(
        '        return await _prepare_run(session, thread_id, request, user)',
        '''        if request.debug:
            audit(thread_id)
        return await _prepare_run(session, thread_id, request, user)''',
    )

    ir, result = _evaluate(source, truthy_when_present=True)

    assert ir.coverage.status == "partial"
    assert ir.paths[0].coverage_status == "partial"
    assert result.status == "unknown"
