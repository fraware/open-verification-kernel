"""Body-helper semantic contracts (#148).

Profile-declared helpers stay unproved until fail-closed implementation
evidence exists. Resource binding is explicit; silent acted_id mapping is
refused. No-op, shadowed, zero-arg, and wrong-resource helpers never PE PASS.
"""

from __future__ import annotations

from ovk.compilers.authorization.body_helper_contracts import (
    analyze_body_helper_implementation,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    BodyAuthorizationHelperSemantics,
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity
from ovk.core.protected_effect_profile import ProtectedEffectProfileConfig


_FAIL_CLOSED_HELPER = """
def require_access(user):
    if user is None:
        raise HTTPException(status_code=403)
""".strip()

_NOOP_HELPER = """
def require_access(user):
    return True
""".strip()


def _profile(
    *,
    helpers: dict[str, BodyAuthorizationHelperSemantics] | None = None,
    with_bypass: bool = False,
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


def _compile(files: dict[str, str], *, profile: FastApiDependencyEffectProfile):
    materials = AuthMaterials(
        base_files=files,
        head_files=files,
        repo="example/body-contracts",
        base_revision="base",
        head_revision="head",
        repository_python_files=files,
    )
    return FastApiDependencyEffectExtractor().compile(materials, profile)


def test_profile_requires_explicit_resource_binding() -> None:
    payload = {
        "schema_version": "ovk.protected_effect_profile.v1",
        "profile_type": "fastapi_dependency_effects_v1",
        "source_paths": ["app/**/*.py"],
        "sink_effects": {"sink": "model.invoke"},
        "body_authorization_helpers": {
            "require_access": {"effects": ["model.invoke"]},
        },
        "principal_parameter": "user",
    }
    import pytest

    with pytest.raises(Exception, match="resource_arg|authorized_resource"):
        ProtectedEffectProfileConfig.model_validate(payload)


def test_fail_closed_helper_with_authorized_resource_can_pass() -> None:
    source = f"""
from fastapi import Depends, FastAPI, HTTPException
app = FastAPI()

{_FAIL_CLOSED_HELPER}

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    require_access(user)
    return sink(user)
""".strip()
    ir = _compile({"app/routes.py": source}, profile=_profile())
    assert ir.guards
    assert ir.guards[0].effectiveness == "established"
    assert ir.guards[0].resource_id == ir.protected_effects[0].resource_id
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status == "pass"


def test_noop_helper_never_pe_pass() -> None:
    source = f"""
from fastapi import Depends, FastAPI
app = FastAPI()

{_NOOP_HELPER}

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    require_access(user)
    return sink(user)
""".strip()
    ir = _compile({"app/routes.py": source}, profile=_profile())
    assert ir.guards
    assert all(guard.effectiveness != "established" for guard in ir.guards)
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"


def test_shadowed_helper_never_pe_pass() -> None:
    files = {
        "app/auth.py": _FAIL_CLOSED_HELPER + "\n",
        "app/routes.py": f"""
from fastapi import Depends, FastAPI
app = FastAPI()

{_NOOP_HELPER}

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    require_access(user)
    return sink(user)
""".strip(),
    }
    evidence = analyze_body_helper_implementation(
        files, helper_name="require_access"
    )
    assert evidence.status == "unproved"
    assert evidence.reason == "helper_definition_shadowed"
    ir = _compile(files, profile=_profile())
    assert all(guard.effectiveness != "established" for guard in ir.guards)
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"


def test_zero_arg_helper_never_matches() -> None:
    source = f"""
from fastapi import Depends, FastAPI, HTTPException
app = FastAPI()

def require_access():
    if False:
        raise HTTPException(status_code=403)

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    require_access()
    return sink(user)
""".strip()
    ir = _compile({"app/routes.py": source}, profile=_profile())
    assert not any("body_auth" in guard.guard_id for guard in ir.guards)
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"


def test_wrong_resource_never_pe_pass() -> None:
    source = f"""
from fastapi import Depends, FastAPI, HTTPException
app = FastAPI()

{_FAIL_CLOSED_HELPER}

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    require_access(user)
    return sink(user)
""".strip()
    profile = _profile(
        helpers={
            "require_access": BodyAuthorizationHelperSemantics(
                authorized_effects=("model.invoke",),
                principal_arg=0,
                authorized_resource="other",
            )
        }
    )
    ir = _compile({"app/routes.py": source}, profile=profile)
    assert not any("body_auth" in guard.guard_id for guard in ir.guards)
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"
