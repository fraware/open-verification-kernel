from __future__ import annotations

import ast

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.route_dependency_effectiveness import (
    infer_route_dependency_effectiveness,
)
from ovk.core.protected_effect_evaluation import (
    evaluate_protected_effect_integrity,
)


SECURE_AUTH = """
from fastapi import Depends

async def require_auth(credentials = Depends(_bearer_scheme)):
    if _active_token is None:
        raise HTTPException(status_code=503)
    if not credentials or credentials.credentials != _active_token:
        raise HTTPException(status_code=401)
""".strip()


FAIL_OPEN_AUTH = """
from fastapi import Depends

async def require_auth(credentials = Depends(_bearer_scheme)):
    if _active_token is None:
        return
    if not credentials or credentials.credentials != _active_token:
        raise HTTPException(status_code=401)
""".strip()


ROUTE = """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.post("", dependencies=[Depends(require_auth)])
async def endpoint():
    await handle_jsonrpc_request({})
""".strip()


PROFILE = FastApiDependencyEffectProfile(
    sink_effects={"handle_jsonrpc_request": "mcp.jsonrpc.dispatch"},
    sink_static_resources={"handle_jsonrpc_request": "mcp_transport"},
    route_dependency_guard_resources={"require_auth": "mcp_transport"},
    route_dependency_guard_effects={
        "require_auth": ("mcp.jsonrpc.dispatch",),
    },
    principal_parameter="$authenticated_caller",
)


def _trees(*, auth_source: str) -> dict[str, ast.Module]:
    return {
        "routes.py": ast.parse(ROUTE),
        "security.py": ast.parse(auth_source),
    }


def _compile(*, auth_source: str):
    files = {
        "routes.py": ROUTE,
        "security.py": auth_source,
    }
    materials = AuthMaterials(
        base_files=dict(files),
        head_files=dict(files),
        repo="example/route-guard-effectiveness",
        base_revision="base",
        head_revision="head",
    )
    return FastApiDependencyEffectExtractor().compile(materials, PROFILE)


def test_fail_closed_bearer_match_emits_effectiveness_evidence() -> None:
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_trees(auth_source=SECURE_AUTH),
        dependency_names={"require_auth"},
    )

    assert len(evidence) == 1
    item = evidence[0]
    assert item.dependency_name == "require_auth"
    assert item.evidence_kind == "fail_closed_bearer_match_v1"
    assert item.credential_parameter == "credentials"
    assert item.credential_attribute == "credentials"
    assert item.token_expression == "_active_token"


def test_explicit_unauthenticated_return_prevents_effectiveness_evidence() -> None:
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_trees(auth_source=FAIL_OPEN_AUTH),
        dependency_names={"require_auth"},
    )

    assert evidence == []


def test_extra_executable_statement_keeps_contract_unproved() -> None:
    source = """
from fastapi import Depends

async def require_auth(credentials = Depends(_bearer_scheme)):
    audit_auth_attempt()
    if _active_token is None:
        raise HTTPException(status_code=503)
    if not credentials or credentials.credentials != _active_token:
        raise HTTPException(status_code=401)
""".strip()
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_trees(auth_source=source),
        dependency_names={"require_auth"},
    )
    assert evidence == []


def test_mismatched_token_expressions_keep_contract_unproved() -> None:
    source = """
from fastapi import Depends

async def require_auth(credentials = Depends(_bearer_scheme)):
    if _active_token is None:
        raise HTTPException(status_code=503)
    if not credentials or credentials.credentials != _other_token:
        raise HTTPException(status_code=401)
""".strip()
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_trees(auth_source=source),
        dependency_names={"require_auth"},
    )
    assert evidence == []


def test_ambiguous_duplicate_dependency_definitions_keep_contract_unproved() -> None:
    trees = {
        "security_a.py": ast.parse(SECURE_AUTH),
        "security_b.py": ast.parse(SECURE_AUTH),
    }
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=trees,
        dependency_names={"require_auth"},
    )
    assert evidence == []


def test_fail_closed_dependency_establishes_route_guard_effectiveness() -> None:
    ir = _compile(auth_source=SECURE_AUTH)
    evaluations = evaluate_protected_effect_integrity(ir)

    assert len(ir.guard_effectiveness_evidence) == 1
    assert len(ir.guards) == 1
    guard = ir.guards[0]
    evidence = ir.guard_effectiveness_evidence[0]
    assert guard.effectiveness == "established"
    assert guard.effectiveness_evidence_ids == [evidence.evidence_id]
    assert len(evaluations) == 1
    assert evaluations[0].status == "pass"


def test_fail_open_dependency_remains_benign_open() -> None:
    ir = _compile(auth_source=FAIL_OPEN_AUTH)
    evaluations = evaluate_protected_effect_integrity(ir)

    assert ir.guard_effectiveness_evidence == []
    assert len(ir.guards) == 1
    assert ir.guards[0].effectiveness == "unproved"
    assert len(evaluations) == 1
    assert evaluations[0].status == "unknown"
    check = next(
        item
        for item in evaluations[0].checks
        if item.dimension == "guard_effectiveness"
    )
    assert check.status == "unknown"
