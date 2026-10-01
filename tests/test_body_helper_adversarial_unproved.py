"""Adversarial body-helper effectiveness cases (#151).

Until a machine-checkable authorization predicate is modeled, profile-declared
helpers whose only implementation signal is a reachable denial-shaped raise
remain unproved. These fixtures must never PE PASS.
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


def _profile(
    *,
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
        principal_parameter="user",
    )


def _compile(files: dict[str, str], *, profile: FastApiDependencyEffectProfile):
    materials = AuthMaterials(
        base_files=files,
        head_files=files,
        repo="example/body-adversarial",
        base_revision="base",
        head_revision="head",
        repository_python_files=files,
    )
    return FastApiDependencyEffectExtractor().compile(materials, profile)


def _handler_calling(helper_body: str, *, call: str = "require_access(user)") -> str:
    return f"""
from fastapi import Depends, FastAPI, HTTPException
import random
app = FastAPI()

{helper_body}

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    {call}
    return sink(user)
""".strip()


def _assert_never_pe_pass(files: dict[str, str], *, helper_name: str = "require_access") -> None:
    evidence = analyze_body_helper_implementation(files, helper_name=helper_name)
    assert evidence.status == "unproved"
    ir = _compile(files, profile=_profile())
    assert all(guard.effectiveness != "established" for guard in ir.guards)
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"


def test_irrelevant_denial_never_pe_pass() -> None:
    """Raise exists but is unrelated to authorization of the principal."""

    helper = """
def require_access(user):
    if 1 == 0:
        pass
    raise HTTPException(status_code=403, detail="maintenance")
""".strip()
    files = {"app/routes.py": _handler_calling(helper)}
    evidence = analyze_body_helper_implementation(files, helper_name="require_access")
    assert evidence.reason == "helper_reachable_raise_insufficient"
    _assert_never_pe_pass(files)


def test_inverted_predicate_never_pe_pass() -> None:
    """Denies admins / permits everyone else — still a reachable raise."""

    helper = """
def require_access(user):
    if user.is_admin:
        raise HTTPException(status_code=403)
""".strip()
    files = {"app/routes.py": _handler_calling(helper)}
    evidence = analyze_body_helper_implementation(files, helper_name="require_access")
    assert evidence.reason == "helper_reachable_raise_insufficient"
    _assert_never_pe_pass(files)


def test_random_denial_never_pe_pass() -> None:
    """Probabilistic deny still contains a reachable HTTPException."""

    helper = """
def require_access(user):
    if random.random() < 0.001:
        raise HTTPException(status_code=403)
""".strip()
    files = {"app/routes.py": _handler_calling(helper)}
    evidence = analyze_body_helper_implementation(files, helper_name="require_access")
    assert evidence.reason == "helper_reachable_raise_insufficient"
    _assert_never_pe_pass(files)


def test_helper_method_identity_mismatch_never_pe_pass() -> None:
    """Profile key matches leaf name but calls a different bound method."""

    files = {
        "app/routes.py": """
from fastapi import Depends, FastAPI, HTTPException
app = FastAPI()

class Gate:
    def require_access(self, user):
        if user is None:
            raise HTTPException(status_code=403)

gate = Gate()

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    gate.require_access(user)
    return sink(user)
""".strip()
    }
    # Leaf name still resolves to a unique FunctionDef in the module walk.
    evidence = analyze_body_helper_implementation(
        files, helper_name="require_access"
    )
    assert evidence.status == "unproved"
    ir = _compile(files, profile=_profile())
    assert all(guard.effectiveness != "established" for guard in ir.guards)
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"


def test_changed_impl_under_unchanged_profile_never_pe_pass() -> None:
    """Head replaces a reviewed helper with an irrelevant raise; profile unchanged."""

    base_helper = """
def require_access(user):
    if user is None or not user.allowed:
        raise HTTPException(status_code=403)
""".strip()
    head_helper = """
def require_access(user):
    if random.random() < 0.001:
        raise HTTPException(status_code=403)
""".strip()
    base_files = {
        "app/helpers.py": base_helper + "\n",
        "app/routes.py": """
from fastapi import Depends, FastAPI, HTTPException
app = FastAPI()

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    require_access(user)
    return sink(user)
""".strip(),
    }
    head_files = {
        "app/helpers.py": "import random\n" + head_helper + "\n",
        "app/routes.py": base_files["app/routes.py"],
    }
    profile = _profile()
    materials = AuthMaterials(
        base_files=base_files,
        head_files=head_files,
        repo="example/body-adversarial",
        base_revision="base",
        head_revision="head",
        repository_python_files=head_files,
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, profile)
    assert all(guard.effectiveness != "established" for guard in ir.guards)
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"
    head_evidence = analyze_body_helper_implementation(
        head_files, helper_name="require_access"
    )
    assert head_evidence.status == "unproved"
    assert head_evidence.reason == "helper_reachable_raise_insufficient"
