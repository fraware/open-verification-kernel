from __future__ import annotations

import ast

from ovk.compilers.authorization.authorization_dependency_contracts import (
    infer_authorization_dependency_contracts,
)


def _infer(source: str):
    return infer_authorization_dependency_contracts(
        parsed_trees={"app.py": ast.parse(source)}
    )


def test_infers_direct_fail_closed_credential_equality() -> None:
    source = """
async def require_auth(credentials = Depends(_bearer)):
    if not credentials or credentials.credentials != ACTIVE_TOKEN:
        raise HTTPException(status_code=401)
""".strip()

    contracts = _infer(source)

    assert len(contracts) == 1
    contract = contracts[0]
    assert contract.qualified_name == "require_auth"
    assert contract.contract_kind == "credential_equality"
    assert contract.credential_expression == "credentials.credentials"
    assert contract.authority_expression == "ACTIVE_TOKEN"
    assert contract.derivation == "direct"


def test_allows_final_explicit_return_none_after_guard() -> None:
    source = """
async def require_auth(credentials = Depends(_bearer)):
    if credentials is None or ACTIVE_TOKEN != credentials.credentials:
        raise HTTPException(status_code=401)
    audit_success()
    return None
""".strip()

    contracts = _infer(source)

    assert len(contracts) == 1
    assert contracts[0].credential_expression == "credentials.credentials"
    assert contracts[0].authority_expression == "ACTIVE_TOKEN"


def test_rejects_fail_open_early_return() -> None:
    source = """
async def require_auth(credentials = Depends(_bearer)):
    if ACTIVE_TOKEN is None:
        return
    if not credentials or credentials.credentials != ACTIVE_TOKEN:
        raise HTTPException(status_code=401)
""".strip()

    assert _infer(source) == []


def test_rejects_no_key_dev_mode_return() -> None:
    source = """
async def require_auth(credentials = Security(_bearer)):
    api_key = configured_api_key()
    if not api_key:
        return
    if not credentials or credentials.credentials != api_key:
        raise HTTPException(status_code=401)
""".strip()

    assert _infer(source) == []


def test_rejects_additional_conditional_even_after_guard() -> None:
    source = """
async def require_auth(credentials = Depends(_bearer)):
    if not credentials or credentials.credentials != ACTIVE_TOKEN:
        raise HTTPException(status_code=401)
    if audit_enabled:
        record_auth()
""".strip()

    assert _infer(source) == []


def test_rejects_delegated_authorization_helper() -> None:
    source = """
async def require_auth(request, credentials = Security(_bearer)):
    validate_api_auth(request=request, credentials=credentials)
""".strip()

    assert _infer(source) == []


def test_rejects_missing_credential_presence_check() -> None:
    source = """
async def require_auth(credentials = Depends(_bearer)):
    if credentials.credentials != ACTIVE_TOKEN:
        raise HTTPException(status_code=401)
""".strip()

    assert _infer(source) == []


def test_rejects_try_wrapped_guard() -> None:
    source = """
async def require_auth(credentials = Depends(_bearer)):
    try:
        if not credentials or credentials.credentials != ACTIVE_TOKEN:
            raise HTTPException(status_code=401)
    except ValueError:
        return
""".strip()

    assert _infer(source) == []

def test_duplicate_dependency_function_names_are_ambiguous() -> None:
    trees = {
        "a.py": ast.parse(
            """
async def require_auth(credentials):
    if not credentials or credentials.credentials != TOKEN_A:
        raise RuntimeError()
""".strip()
        ),
        "b.py": ast.parse(
            """
async def require_auth(credentials):
    if not credentials or credentials.credentials != TOKEN_B:
        raise RuntimeError()
""".strip()
        ),
    }

    assert infer_authorization_dependency_contracts(
        parsed_trees=trees
    ) == []

