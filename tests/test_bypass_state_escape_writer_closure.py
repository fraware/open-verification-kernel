"""Request/state escape analysis + interprocedural writer closure (#156)."""

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


def test_helper_state_formal_client_write_cannot_authorize() -> None:
    """``write_state(request.state, client)`` must not leave only the literal write."""

    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = value

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"
    assert findings[0].write_count >= 2


def test_helper_state_formal_client_write_is_violated() -> None:
    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = value

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_dict_mutation_beside_literal_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    request.state.__dict__["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_vars_state_mutation_beside_literal_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    state = request.state
    vars(state)["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_getattr_dict_mutation_beside_literal_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    getattr(request.state, "__dict__")["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_dict_attr_alias_mutation_beside_literal_cannot_authorize() -> None:
    """``d = request.state.__dict__; d[field]=client`` must not authorize."""

    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    d = request.state.__dict__
    d["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_object_getattribute_dict_mutation_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    object.__getattribute__(request.state, "__dict__")["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_state_getattribute_dict_mutation_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    request.state.__getattribute__("__dict__")["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_operator_attrgetter_dict_mutation_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
import operator
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    operator.attrgetter("__dict__")(request.state)["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_tuple_unpack_state_escape_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    (s,) = (request.state,)
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_list_unpack_state_escape_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    [s] = [request.state]
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_walrus_dict_mutation_beside_literal_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    (d := request.state.__dict__)["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_for_iter_state_pack_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    for s in [request.state]:
        s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_list_append_state_escape_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    bucket = []
    bucket.append(request.state)
    bucket[0].bypass_filter = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_unknown_helper_receiving_state_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    external_mutate(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_unknown_method_receiving_request_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    request.app.dependency_overrides.clear()
    helper.configure(request)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_literal_only_helper_passthrough_still_authorizes() -> None:
    """Resolved local callee with only literal write may still authorize."""

    findings = analyze_bypass_authority(
        """
def mark_trusted(state):
    state.bypass_filter = True

def handler(request):
    mark_trusted(request.state)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "authorized"


def test_cross_module_helper_state_formal_cannot_authorize() -> None:
    findings = analyze_bypass_authority_unit(
        {
            "app/helpers.py": """
def write_state(state, value):
    state.bypass_filter = value
""".strip(),
            "app/routes.py": """
def write_state(state, value):
    state.bypass_filter = value

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/helpers.py", "app/routes.py"),
    )
    # Ambiguous bare name ``write_state`` across the unit must not authorize.
    assert findings[0].status != "authorized"


def test_pe_compile_refuses_established_for_state_helper_client_write() -> None:
    files = {
        "app/middleware.py": """
def write_state(state, value):
    state.bypass_filter = value

def attach_trusted(request):
    request.state.bypass_filter = True
""".strip(),
        "app/routes.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    attach_trusted(request)
    write_state(request.state, bypass_filter)
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip(),
    }
    # Routes imports are unresolved unless helpers are inlined for PE compile;
    # put both writers in the route module for the PE surface check.
    files = {
        "app/routes.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

def write_state(state, value):
    state.bypass_filter = value

def attach_trusted(request):
    request.state.bypass_filter = True

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    attach_trusted(request)
    write_state(request.state, bypass_filter)
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
        repo="example/escape-bypass",
        base_revision="base",
        head_revision="head",
        repository_python_files=files,
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, profile)
    assert ir.bypass_authority_evidence
    assert all(
        item.status != "established" for item in ir.bypass_authority_evidence
    )
