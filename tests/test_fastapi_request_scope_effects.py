from __future__ import annotations

from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.core.protected_effect_evaluation import (
    evaluate_protected_effect_integrity,
)


PROFILE = FastApiDependencyEffectProfile(
    sink_effects={
        "delete_document": "workspace.document.delete",
    },
    sink_identity_args={"delete_document": 0},
    sink_scope_keywords={"delete_document": "scope"},
    sink_missing_scope_unconstrained=frozenset({"delete_document"}),
    request_scope_guards={
        "_deny": ("workspace.document.delete",),
    },
    request_scope_guard_request_args={"_deny": 0},
    request_scope_accessors={"get_scope": 0},
    principal_parameter="request",
)


SECURE = """
from fastapi import APIRouter, Request
router = APIRouter()

@router.delete("/{doc_id}")
def api_delete_document(doc_id: int, request: Request):
    denied = _deny(request, None, "editor")
    if denied:
        return denied
    request.app.state.db.delete_document(
        doc_id, None, scope=get_scope(request)
    )
    return {"success": True}
""".strip()


VULNERABLE = """
from fastapi import APIRouter, Request
router = APIRouter()

@router.delete("/{doc_id}")
def api_delete_document(doc_id: int, request: Request):
    denied = _deny(request, None, "editor")
    if denied:
        return denied
    request.app.state.db.delete_document(doc_id, None)
    return {"success": True}
""".strip()


IGNORED_DENIAL = """
from fastapi import APIRouter, Request
router = APIRouter()

@router.delete("/{doc_id}")
def api_delete_document(doc_id: int, request: Request):
    denied = _deny(request, None, "editor")
    request.app.state.db.delete_document(
        doc_id, None, scope=get_scope(request)
    )
    return {"success": True}
""".strip()


WRONG_REQUEST_SCOPE = """
from fastapi import APIRouter, Request
router = APIRouter()

@router.delete("/{doc_id}")
def api_delete_document(
    doc_id: int,
    request: Request,
    other_request: Request,
):
    denied = _deny(request, None, "editor")
    if denied:
        return denied
    request.app.state.db.delete_document(
        doc_id, None, scope=get_scope(other_request)
    )
    return {"success": True}
""".strip()


def _evaluate(source: str):
    materials = materials_from_pair(
        path="src/routes_fastapi/document_routes.py",
        base_source=source,
        head_source=source,
        repo="jwvanderstam/LocalChat",
        base_revision="base",
        head_revision="head",
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, PROFILE)
    result = evaluate_protected_effect_integrity(ir)[0]
    return ir, result


def test_fail_closed_request_guard_and_same_request_scope_pass() -> None:
    ir, result = _evaluate(SECURE)

    assert ir.coverage.status == "complete"
    assert len(ir.guards) == 1
    assert len(ir.resource_bindings) == 1
    assert result.status == "pass"

    binding = ir.resource_bindings[0]
    resources = {item.resource_id: item for item in ir.resources}
    authorized = resources[binding.authorized_resource_id]
    acted = resources[binding.acted_resource_id]
    assert authorized.identity_term is not None
    assert acted.scope_term is not None
    assert authorized.identity_term == acted.scope_term
    assert authorized.identity_term.value == "$request_scope:request"


def test_historical_unscoped_database_call_is_refuted() -> None:
    ir, result = _evaluate(VULNERABLE)

    assert ir.coverage.status == "complete"
    assert result.status in {"fail", "unknown"}
    evidence = result.resource_binding_evidence[0]
    if result.status == "fail":
        assert evidence.counterexample is not None
        assert evidence.counterexample["relation"] == "same_tenant"
    else:
        assert evidence.engine == "z3-unavailable"
        assert evidence.counterexample is None


def test_calling_guard_without_fail_closed_result_check_is_not_authorization() -> None:
    ir, result = _evaluate(IGNORED_DENIAL)

    assert ir.coverage.status == "partial"
    assert any(
        "request_scope_guard_not_fail_closed:_deny" in reason
        for reason in ir.coverage.unsupported_constructs
    )
    assert result.status == "unknown"
    assert ir.guards == []


def test_scope_accessor_on_different_request_is_refuted() -> None:
    ir, result = _evaluate(WRONG_REQUEST_SCOPE)

    assert ir.coverage.status == "complete"
    assert result.status in {"fail", "unknown"}
    evidence = result.resource_binding_evidence[0]
    if result.status == "fail":
        assert evidence.counterexample is not None
        assert evidence.counterexample["relation"] == "same_tenant"
    else:
        assert evidence.engine == "z3-unavailable"
        assert evidence.counterexample is None
