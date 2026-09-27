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
    assert item.comparison_kind == "direct_inequality"


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

SECURE_HEADER_AUTH = """
import secrets
from fastapi import Header

async def require_internal_token(
    x_internal_token: str | None = Header(None),
) -> None:
    configured_token = AppVars.API_INTERNAL_TOKEN.get_secret_value()
    if not configured_token:
        raise HTTPException(status_code=503)
    if not x_internal_token or not secrets.compare_digest(
        x_internal_token, configured_token
    ):
        raise HTTPException(status_code=401)
""".strip()


FAIL_OPEN_HEADER_AUTH = """
import secrets
from fastapi import Header

async def require_internal_token(
    x_internal_token: str | None = Header(None),
) -> None:
    configured_token = AppVars.API_INTERNAL_TOKEN.get_secret_value()
    if not configured_token:
        return
    if not x_internal_token or not secrets.compare_digest(
        x_internal_token, configured_token
    ):
        raise HTTPException(status_code=401)
""".strip()


HEADER_ROUTE = """
from fastapi import APIRouter, Depends

router = APIRouter(
    dependencies=[Depends(require_internal_token)],
)

@router.post("")
async def endpoint():
    await invoke_model({})
""".strip()


HEADER_PROFILE = FastApiDependencyEffectProfile(
    sink_effects={"invoke_model": "ai.chat.invoke"},
    sink_static_resources={"invoke_model": "ai_chat_service"},
    route_dependency_guard_resources={
        "require_internal_token": "ai_chat_service"
    },
    route_dependency_guard_effects={
        "require_internal_token": ("ai.chat.invoke",),
    },
    principal_parameter="$internal_api_caller",
)


def _header_trees(
    *,
    auth_source: str,
) -> dict[str, ast.Module]:
    return {
        "routes.py": ast.parse(HEADER_ROUTE),
        "security.py": ast.parse(auth_source),
    }


def _compile_header(*, auth_source: str):
    files = {
        "routes.py": HEADER_ROUTE,
        "security.py": auth_source,
    }
    materials = AuthMaterials(
        base_files=dict(files),
        head_files=dict(files),
        repo="example/header-shared-secret",
        base_revision="base",
        head_revision="head",
    )
    return FastApiDependencyEffectExtractor().compile(
        materials,
        HEADER_PROFILE,
    )


def test_fail_closed_header_shared_secret_emits_distinct_evidence() -> None:
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_header_trees(auth_source=SECURE_HEADER_AUTH),
        dependency_names={"require_internal_token"},
    )

    assert len(evidence) == 1
    item = evidence[0]
    assert item.dependency_name == "require_internal_token"
    assert item.evidence_kind == "fail_closed_header_shared_secret_v1"
    assert item.credential_parameter == "x_internal_token"
    assert item.credential_attribute is None
    assert (
        item.token_expression
        == "AppVars.API_INTERNAL_TOKEN.get_secret_value()"
    )
    assert item.comparison_kind == "secrets_compare_digest"


def test_fail_open_header_shared_secret_remains_unproved() -> None:
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_header_trees(auth_source=FAIL_OPEN_HEADER_AUTH),
        dependency_names={"require_internal_token"},
    )
    assert evidence == []


def test_header_shared_secret_requires_token_presence_guard() -> None:
    source = """
import secrets
from fastapi import Header

async def require_internal_token(
    x_internal_token: str | None = Header(None),
) -> None:
    configured_token = AppVars.API_INTERNAL_TOKEN.get_secret_value()
    if not x_internal_token or not secrets.compare_digest(
        x_internal_token, configured_token
    ):
        raise HTTPException(status_code=401)
""".strip()
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_header_trees(auth_source=source),
        dependency_names={"require_internal_token"},
    )
    assert evidence == []


def test_header_shared_secret_requires_same_token_alias_in_comparison() -> None:
    source = """
import secrets
from fastapi import Header

async def require_internal_token(
    x_internal_token: str | None = Header(None),
) -> None:
    configured_token = AppVars.API_INTERNAL_TOKEN.get_secret_value()
    if not configured_token:
        raise HTTPException(status_code=503)
    if not x_internal_token or not secrets.compare_digest(
        x_internal_token, other_token
    ):
        raise HTTPException(status_code=401)
""".strip()
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_header_trees(auth_source=source),
        dependency_names={"require_internal_token"},
    )
    assert evidence == []


def test_header_shared_secret_requires_negated_compare_digest() -> None:
    source = """
import secrets
from fastapi import Header

async def require_internal_token(
    x_internal_token: str | None = Header(None),
) -> None:
    configured_token = AppVars.API_INTERNAL_TOKEN.get_secret_value()
    if not configured_token:
        raise HTTPException(status_code=503)
    if not x_internal_token or secrets.compare_digest(
        x_internal_token, configured_token
    ):
        raise HTTPException(status_code=401)
""".strip()
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_header_trees(auth_source=source),
        dependency_names={"require_internal_token"},
    )
    assert evidence == []


def test_header_shared_secret_requires_header_none_parameter() -> None:
    source = """
import secrets
from fastapi import Header

async def require_internal_token(
    x_internal_token: str = Header("trusted-default"),
) -> None:
    configured_token = AppVars.API_INTERNAL_TOKEN.get_secret_value()
    if not configured_token:
        raise HTTPException(status_code=503)
    if not x_internal_token or not secrets.compare_digest(
        x_internal_token, configured_token
    ):
        raise HTTPException(status_code=401)
""".strip()
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_header_trees(auth_source=source),
        dependency_names={"require_internal_token"},
    )
    assert evidence == []


def test_header_shared_secret_rejects_credential_derived_token_source() -> None:
    source = """
import secrets
from fastapi import Header

async def require_internal_token(
    x_internal_token: str | None = Header(None),
) -> None:
    configured_token = x_internal_token.strip()
    if not configured_token:
        raise HTTPException(status_code=503)
    if not x_internal_token or not secrets.compare_digest(
        x_internal_token, configured_token
    ):
        raise HTTPException(status_code=401)
""".strip()
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_header_trees(auth_source=source),
        dependency_names={"require_internal_token"},
    )
    assert evidence == []


def test_header_shared_secret_rejects_extra_executable_statement() -> None:
    source = """
import secrets
from fastapi import Header

async def require_internal_token(
    x_internal_token: str | None = Header(None),
) -> None:
    configured_token = AppVars.API_INTERNAL_TOKEN.get_secret_value()
    audit_auth_attempt()
    if not configured_token:
        raise HTTPException(status_code=503)
    if not x_internal_token or not secrets.compare_digest(
        x_internal_token, configured_token
    ):
        raise HTTPException(status_code=401)
""".strip()
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_header_trees(auth_source=source),
        dependency_names={"require_internal_token"},
    )
    assert evidence == []


def test_fail_closed_header_dependency_establishes_inherited_guard() -> None:
    ir = _compile_header(auth_source=SECURE_HEADER_AUTH)
    evaluations = evaluate_protected_effect_integrity(ir)

    assert len(ir.guard_effectiveness_evidence) == 1
    evidence = ir.guard_effectiveness_evidence[0]
    assert evidence.evidence_kind == "fail_closed_header_shared_secret_v1"
    assert len(ir.guards) == 1
    assert ir.guards[0].effectiveness == "established"
    assert ir.guards[0].effectiveness_evidence_ids == [
        evidence.evidence_id
    ]
    assert len(evaluations) == 1
    assert evaluations[0].status == "pass"
    assert evaluations[0].extraction_coverage == "complete"


def test_fail_open_header_dependency_stays_benign_open() -> None:
    ir = _compile_header(auth_source=FAIL_OPEN_HEADER_AUTH)
    evaluations = evaluate_protected_effect_integrity(ir)

    assert ir.guard_effectiveness_evidence == []
    assert len(ir.guards) == 1
    assert ir.guards[0].effectiveness == "unproved"
    assert len(evaluations) == 1
    assert evaluations[0].status == "unknown"
    assert evaluations[0].extraction_coverage == "complete"

SECURE_APIKEY_AUTH = """
import hmac
import os
from fastapi import Security
from fastapi.security import APIKeyHeader

API_KEY_ENV_VAR = "C360_API_KEY"
API_KEY_HEADER_NAME = "X-API-Key"
_api_key_header = APIKeyHeader(
    name=API_KEY_HEADER_NAME,
    auto_error=False,
)

def require_api_key(
    provided_key: str | None = Security(_api_key_header),
) -> None:
    expected_key = os.environ.get(API_KEY_ENV_VAR)
    if not expected_key:
        raise HTTPException(status_code=503)
    if not provided_key or not hmac.compare_digest(
        provided_key, expected_key
    ):
        raise HTTPException(status_code=401)
    return None
""".strip()


FAIL_OPEN_APIKEY_AUTH = SECURE_APIKEY_AUTH.replace(
    "if not expected_key:\n        raise HTTPException(status_code=503)",
    "if not expected_key:\n        return None",
)


APIKEY_ROUTE = """
from fastapi import FastAPI, Depends

app = FastAPI()

@app.post("/predict", dependencies=[Depends(require_api_key)])
def predict(payload: dict):
    if not payload:
        raise HTTPException(status_code=400)
    return predict_model(payload)
""".strip()


APIKEY_PROFILE = FastApiDependencyEffectProfile(
    sink_effects={"predict_model": "customer360.bp1.predict"},
    sink_static_resources={
        "predict_model": "bp1_prediction_execution"
    },
    route_dependency_guard_resources={
        "require_api_key": "bp1_prediction_execution"
    },
    route_dependency_guard_effects={
        "require_api_key": ("customer360.bp1.predict",),
    },
    principal_parameter="$api_key_caller",
)


def _apikey_trees(*, auth_source: str) -> dict[str, ast.Module]:
    return {
        "routes.py": ast.parse(APIKEY_ROUTE),
        "security.py": ast.parse(auth_source),
    }


def _compile_apikey(*, auth_source: str):
    files = {
        "routes.py": APIKEY_ROUTE,
        "security.py": auth_source,
    }
    materials = AuthMaterials(
        base_files=dict(files),
        head_files=dict(files),
        repo="example/apikey-shared-secret",
        base_revision="base",
        head_revision="head",
    )
    return FastApiDependencyEffectExtractor().compile(
        materials,
        APIKEY_PROFILE,
    )


def test_fail_closed_apikeyheader_shared_secret_emits_evidence() -> None:
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_apikey_trees(auth_source=SECURE_APIKEY_AUTH),
        dependency_names={"require_api_key"},
    )

    assert len(evidence) == 1
    item = evidence[0]
    assert item.dependency_name == "require_api_key"
    assert (
        item.evidence_kind
        == "fail_closed_apikeyheader_shared_secret_v1"
    )
    assert item.credential_parameter == "provided_key"
    assert item.credential_attribute is None
    assert item.token_expression == "os.environ.get(API_KEY_ENV_VAR)"
    assert item.comparison_kind == "hmac_compare_digest"


def test_apikeyheader_requires_fail_closed_missing_server_secret() -> None:
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_apikey_trees(auth_source=FAIL_OPEN_APIKEY_AUTH),
        dependency_names={"require_api_key"},
    )
    assert evidence == []


def test_apikeyheader_requires_auto_error_false_scheme() -> None:
    source = SECURE_APIKEY_AUTH.replace(
        "auto_error=False",
        "auto_error=True",
    )
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_apikey_trees(auth_source=source),
        dependency_names={"require_api_key"},
    )
    assert evidence == []


def test_apikeyheader_rejects_non_apikey_security_scheme() -> None:
    source = SECURE_APIKEY_AUTH.replace(
        "APIKeyHeader(\n    name=API_KEY_HEADER_NAME,\n    auto_error=False,\n)",
        "HTTPBearer(auto_error=False)",
    )
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_apikey_trees(auth_source=source),
        dependency_names={"require_api_key"},
    )
    assert evidence == []


def test_apikeyheader_requires_hmac_compare_digest() -> None:
    source = SECURE_APIKEY_AUTH.replace(
        "hmac.compare_digest",
        "secrets.compare_digest",
    )
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_apikey_trees(auth_source=source),
        dependency_names={"require_api_key"},
    )
    assert evidence == []


def test_apikeyheader_rejects_environment_secret_fallback() -> None:
    source = SECURE_APIKEY_AUTH.replace(
        "os.environ.get(API_KEY_ENV_VAR)",
        'os.environ.get(API_KEY_ENV_VAR, "development-default")',
    )
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_apikey_trees(auth_source=source),
        dependency_names={"require_api_key"},
    )
    assert evidence == []


def test_apikeyheader_rejects_extra_executable_statement() -> None:
    source = SECURE_APIKEY_AUTH.replace(
        "expected_key = os.environ.get(API_KEY_ENV_VAR)",
        (
            "expected_key = os.environ.get(API_KEY_ENV_VAR)\n"
            "    audit_auth_attempt()"
        ),
    )
    evidence = infer_route_dependency_effectiveness(
        parsed_trees=_apikey_trees(auth_source=source),
        dependency_names={"require_api_key"},
    )
    assert evidence == []


def test_fail_closed_apikeyheader_dependency_establishes_guard() -> None:
    ir = _compile_apikey(auth_source=SECURE_APIKEY_AUTH)
    evaluations = evaluate_protected_effect_integrity(ir)

    assert len(ir.guard_effectiveness_evidence) == 1
    evidence = ir.guard_effectiveness_evidence[0]
    assert (
        evidence.evidence_kind
        == "fail_closed_apikeyheader_shared_secret_v1"
    )
    assert len(ir.guards) == 1
    assert ir.guards[0].effectiveness == "established"
    assert ir.guards[0].effectiveness_evidence_ids == [
        evidence.evidence_id
    ]
    assert len(evaluations) == 1
    assert evaluations[0].status == "pass"
    assert evaluations[0].extraction_coverage == "complete"


def test_fail_open_apikeyheader_dependency_stays_benign_open() -> None:
    ir = _compile_apikey(auth_source=FAIL_OPEN_APIKEY_AUTH)
    evaluations = evaluate_protected_effect_integrity(ir)

    assert ir.guard_effectiveness_evidence == []
    assert len(ir.guards) == 1
    assert ir.guards[0].effectiveness == "unproved"
    assert len(evaluations) == 1
    assert evaluations[0].status == "unknown"
    assert evaluations[0].extraction_coverage == "complete"

