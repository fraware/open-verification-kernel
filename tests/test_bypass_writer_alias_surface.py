"""Bypass writer surface alias / poison coverage (#153)."""

from __future__ import annotations

from ovk.compilers.authorization.bypass_authority import (
    ClosedWorldScopeProof,
    analyze_bypass_authority,
    analyze_bypass_authority_unit,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)


def _scope(*paths: str) -> ClosedWorldScopeProof:
    return ClosedWorldScopeProof(
        accounted_paths=tuple(paths),
        source_roots=(".",),
    )


def test_request_alias_write_is_accounted() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request):
    req = request
    req.state.bypass_filter = True

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
    )
    assert findings[0].status == "authorized"
    assert findings[0].write_count >= 1


def test_state_alias_write_is_accounted() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request):
    state = request.state
    state.bypass_filter = True

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
    )
    assert findings[0].status == "authorized"
    assert findings[0].write_count >= 1


def test_unknown_state_field_mutation_poisons_unknown() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request):
    request.state.bypass_filter = True

def client_writer(obj, bypass_filter):
    obj.state.bypass_filter = bypass_filter

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
    )
    assert findings[0].status == "unknown"
    assert findings[0].write_count >= 2


def test_subscript_state_mutation_poisons_unknown() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request, bypass_filter):
    request.state["bypass_filter"] = bypass_filter

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
    )
    assert findings[0].status != "authorized"


def test_setattr_on_request_alias_poisons_or_accounts() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request, bypass_filter):
    req = request
    setattr(req.state, "bypass_filter", bypass_filter)

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
    )
    assert findings[0].status != "authorized"


def test_req_state_client_writer_cannot_establish_with_trusted_literal() -> None:
    """Regression: omitted ``req.state`` client write must not leave established authority."""

    findings = analyze_bypass_authority_unit(
        {
            "app/trusted.py": """
def trusted_writer(request):
    request.state.bypass_filter = True
""".strip(),
            "app/client.py": """
def client_writer(req, bypass_filter):
    req.state.bypass_filter = bypass_filter
""".strip(),
            "app/routes.py": """
def handler(request):
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/routes.py",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/trusted.py", "app/client.py", "app/routes.py"),
    )
    assert findings
    assert all(item.status != "authorized" for item in findings)
    assert findings[0].write_count >= 2


def test_getattr_state_alias_client_write_cannot_establish() -> None:
    """``state = getattr(request, \"state\")`` must not omit a client write."""

    findings = analyze_bypass_authority(
        """
def middleware(request, bypass_filter):
    request.state.bypass_filter = True
    state = getattr(request, "state")
    state.bypass_filter = bypass_filter

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
    )
    assert findings[0].status != "authorized"
    assert findings[0].write_count >= 2


def test_nested_function_client_write_cannot_establish() -> None:
    findings = analyze_bypass_authority(
        """
def middleware(request, bypass_filter):
    request.state.bypass_filter = True
    def inner():
        request.state.bypass_filter = bypass_filter
    inner()

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
    )
    assert findings[0].status != "authorized"
    assert findings[0].write_count >= 2


def test_class_method_client_write_cannot_establish() -> None:
    findings = analyze_bypass_authority(
        """
class Middleware:
    def attach_client(self, request, bypass_filter):
        request.state.bypass_filter = bypass_filter

def trusted(request):
    request.state.bypass_filter = True

def handler(request):
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
    )
    assert findings[0].status != "authorized"
    assert findings[0].write_count >= 2


def test_pe_compile_refuses_established_when_req_client_writer_present() -> None:
    files = {
        "app/middleware.py": """
def attach(request):
    request.state.bypass_filter = True

def attach_client(req, bypass_filter):
    req.state.bypass_filter = bypass_filter
""".strip(),
        "app/routes.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip(),
    }
    profile = FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_parameter="user",
    )
    materials = AuthMaterials(
        base_files=files,
        head_files=files,
        repo="example/alias-bypass",
        base_revision="base",
        head_revision="head",
        repository_python_files=files,
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, profile)
    assert ir.bypass_authority_evidence
    assert all(
        item.status != "established" for item in ir.bypass_authority_evidence
    )
