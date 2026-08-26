"""Adversarial tests for source-profile/compiler claim identity.

An unrecognized or framework-incompatible profile request must never be
silently executed by a fallback compiler while retaining the requested profile
name in evidence. Such a mismatch would overstate the support contract that
actually governed compilation.
"""

from __future__ import annotations

from ovk.core.authorization_compiler import compile_authorization_obligation


_FASTAPI_BASE = """
from fastapi import Depends, FastAPI

def require_admin():
    return "admin"

app = FastAPI()

@app.get("/admin", dependencies=[Depends(require_admin)])
def admin():
    return {}
""".strip()

_FASTAPI_HEAD = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/admin")
def admin():
    return {}
""".strip()


def _input(*, profile_id: str, framework: str = "fastapi") -> dict:
    return {
        "framework": framework,
        "source_profile_id": profile_id,
        "materials": {
            "path": "app.py",
            "base_source": _FASTAPI_BASE,
            "head_source": _FASTAPI_HEAD,
        },
    }


def test_unknown_requested_profile_cannot_mint_profile_qualified_compiler_identity() -> None:
    requested = "authorization.fastapi.unregistered_v99"
    obligation = compile_authorization_obligation(
        _input(profile_id=requested),
        repo="example/repo",
        base_sha="base",
        head_sha="head",
    )

    assert requested not in obligation.compiler_id
    assert obligation.abstraction.get("source_compiler") is None
    assert obligation.abstraction.get("strict_allow_permitted") is False
    assert obligation.coverage.status == "unknown"
    assert any(
        "unknown_source_profile" in item
        for item in obligation.coverage.unsupported_constructs
    )


def test_framework_incompatible_profile_request_fails_closed() -> None:
    obligation = compile_authorization_obligation(
        _input(profile_id="authorization.express.ast_v1", framework="fastapi"),
        repo="example/repo",
        base_sha="base",
        head_sha="head",
    )

    assert "authorization.express.ast_v1" not in obligation.compiler_id
    assert obligation.abstraction.get("strict_allow_permitted") is False
    assert obligation.coverage.status == "unknown"
    assert any(
        "source_profile_framework_mismatch" in item
        for item in obligation.coverage.unsupported_constructs
    )


def test_known_matching_profile_binds_exact_compiler_identity() -> None:
    requested = "authorization.fastapi.ast_v1"
    obligation = compile_authorization_obligation(
        _input(profile_id=requested),
        repo="example/repo",
        base_sha="base",
        head_sha="head",
    )

    assert obligation.compiler_id == f"ovk.authorization.fastapi.profile:{requested}"
    assert obligation.abstraction.get("source_compiler") == obligation.compiler_id
