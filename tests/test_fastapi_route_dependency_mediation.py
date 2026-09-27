from __future__ import annotations

import pytest

from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.core.protected_effect_evaluation import (
    evaluate_protected_effect_integrity,
)
from ovk.core.protected_effect_profile import ProtectedEffectProfileConfig


PROFILE = FastApiDependencyEffectProfile(
    sink_effects={"handle_jsonrpc_request": "mcp.module.execute"},
    sink_static_resources={"handle_jsonrpc_request": "mcp_transport"},
    route_dependency_guard_resources={"require_auth": "mcp_transport"},
    route_dependency_guard_effects={
        "require_auth": ("mcp.module.execute",),
    },
    principal_parameter="$authenticated_caller",
)


def _compile(source: str, profile: FastApiDependencyEffectProfile = PROFILE):
    materials = materials_from_pair(
        path="routes.py",
        base_source=source,
        head_source=source,
        repo="example/route-mediation",
        base_revision="base",
        head_revision="head",
    )
    return FastApiDependencyEffectExtractor().compile(materials, profile)


def _evaluation(source: str, profile: FastApiDependencyEffectProfile = PROFILE):
    ir = _compile(source, profile)
    evaluations = evaluate_protected_effect_integrity(ir)
    assert len(evaluations) == 1
    return ir, evaluations[0]


def test_direct_route_dependency_completely_mediates_static_effect() -> None:
    source = """
from fastapi import APIRouter, Depends, Request

router = APIRouter()

@router.post("", dependencies=[Depends(require_auth)])
async def mcp_post(request: Request):
    if request.headers.get("x-stop"):
        return None

    items = await request.json()
    responses = []
    for item in items:
        result = await handle_jsonrpc_request(item)
        if result is not None:
            responses.append(result)
    return responses
""".strip()

    ir, evaluation = _evaluation(source)

    # Repository-wide syntax remains partial because the handler contains
    # branching/iteration outside the general source profile.
    assert ir.coverage.status == "partial"

    # The route dependency executes before every handler path and both guard and
    # effect refer to the same governed static capability. Internal control flow
    # therefore cannot bypass this authorization decision.
    assert evaluation.extraction_coverage == "complete"
    assert evaluation.status == "pass"
    assert len(ir.guards) == 1
    assert ir.guards[0].resource_id == ir.protected_effects[0].resource_id


def test_missing_route_dependency_is_not_mistaken_for_authorization() -> None:
    source = """
from fastapi import APIRouter, Request

router = APIRouter()

@router.post("")
async def mcp_post(request: Request):
    items = await request.json()
    for item in items:
        await handle_jsonrpc_request(item)
""".strip()

    ir, evaluation = _evaluation(source)

    assert ir.guards == []
    assert evaluation.status == "fail"
    guard_check = next(
        check
        for check in evaluation.checks
        if check.dimension == "guard_presence"
    )
    assert guard_check.status == "violated"


def test_dependency_factory_is_outside_direct_route_dependency_subset() -> None:
    source = """
from fastapi import APIRouter, Depends, Request

router = APIRouter()

@router.post("", dependencies=[Depends(require_auth())])
async def mcp_post(request: Request):
    await handle_jsonrpc_request(await request.json())
""".strip()

    ir, evaluation = _evaluation(source)

    assert ir.guards == []
    assert evaluation.status == "fail"


def test_route_dependency_cannot_authorize_a_different_static_resource() -> None:
    profile = FastApiDependencyEffectProfile(
        sink_effects={"handle_jsonrpc_request": "mcp.module.execute"},
        sink_static_resources={"handle_jsonrpc_request": "mcp_transport"},
        route_dependency_guard_resources={"require_auth": "admin_console"},
        route_dependency_guard_effects={
            "require_auth": ("mcp.module.execute",),
        },
        principal_parameter="$authenticated_caller",
    )
    source = """
from fastapi import APIRouter, Depends, Request

router = APIRouter()

@router.post("", dependencies=[Depends(require_auth)])
async def mcp_post(request: Request):
    await handle_jsonrpc_request(await request.json())
""".strip()

    ir, evaluation = _evaluation(source, profile)

    assert len(ir.guards) == 1
    assert ir.guards[0].resource_id != ir.protected_effects[0].resource_id
    assert evaluation.status == "fail"
    resource_check = next(
        check
        for check in evaluation.checks
        if check.dimension == "resource_binding"
    )
    assert resource_check.status == "violated"


def test_profile_rejects_unpaired_route_dependency_semantics() -> None:
    with pytest.raises(ValueError, match="identical keys"):
        ProtectedEffectProfileConfig(
            source_paths=["routes.py"],
            sink_effects={"handle_jsonrpc_request": "mcp.module.execute"},
            sink_static_resources={
                "handle_jsonrpc_request": "mcp_transport"
            },
            route_dependency_guard_resources={
                "require_auth": "mcp_transport"
            },
            route_dependency_guard_effects={},
        )


def test_profile_rejects_route_dependency_effect_outside_sink_model() -> None:
    with pytest.raises(ValueError, match="absent from sink_effects"):
        ProtectedEffectProfileConfig(
            source_paths=["routes.py"],
            sink_effects={"handle_jsonrpc_request": "mcp.module.execute"},
            sink_static_resources={
                "handle_jsonrpc_request": "mcp_transport"
            },
            route_dependency_guard_resources={
                "require_auth": "mcp_transport"
            },
            route_dependency_guard_effects={
                "require_auth": ["different.effect"]
            },
        )


def test_static_sink_rejects_dynamic_identity_configuration() -> None:
    with pytest.raises(ValueError, match="static sink resources cannot combine"):
        ProtectedEffectProfileConfig(
            source_paths=["routes.py"],
            sink_effects={"dispatch": "mcp.dispatch"},
            sink_static_resources={"dispatch": "mcp_transport"},
            sink_identity_args={"dispatch": 0},
            route_dependency_guard_resources={
                "require_auth": "mcp_transport"
            },
            route_dependency_guard_effects={
                "require_auth": ["mcp.dispatch"]
            },
        )


def test_runtime_profile_rejects_contradictory_static_sink_semantics() -> None:
    with pytest.raises(ValueError, match="static sink resources cannot combine"):
        FastApiDependencyEffectProfile(
            sink_effects={"dispatch": "mcp.dispatch"},
            sink_static_resources={"dispatch": "mcp_transport"},
            sink_scope_keywords={"dispatch": "workspace_id"},
            route_dependency_guard_resources={
                "require_auth": "mcp_transport"
            },
            route_dependency_guard_effects={
                "require_auth": ("mcp.dispatch",)
            },
        )

def test_unrelated_empty_string_literal_does_not_break_route_summary() -> None:
    source = """
from fastapi import APIRouter, Depends, Request

router = APIRouter()

@router.post("", dependencies=[Depends(require_auth)])
async def mcp_post(request: Request):
    token = request.headers.get("x-token", "")
    await handle_jsonrpc_request(token)
""".strip()

    ir, evaluation = _evaluation(source)

    assert evaluation.status == "pass"
    assert evaluation.extraction_coverage == "complete"
    assert len(ir.protected_effects) == 1

