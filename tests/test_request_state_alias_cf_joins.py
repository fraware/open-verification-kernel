"""Request/state alias CF joins + guarded match exhaustiveness (#171).

Closes false PASSes where:
1. Guarded final ``case _ if cond:`` was treated as exhaustive.
2. A shared mutable request/state alias env let one CF branch erase
   aliases before another branch's client write was scanned.
3. Cross-kind CF join dropped a name present as request on one predecessor
   and state on another, omitting governed may-state writes.
4. Interprocedural transfer promoted caller may-aliases to callee must-aliases.
5. Expression-level ``IfExp`` cross-kind arms were unclassified (poisoned),
   so only a literal ``request.state.field = True`` remained and could
   yield ``source_proved_server_authority_write``.
6. Expression-level ``BoolOp`` (``and``/``or``) operands were unclassified,
   so ``x = flag and request.state or request`` omitted client writes through ``x``.
7. Match subject-capturing ``as`` patterns poisoned binders, so
   ``match request.state: case object() as x:`` omitted writes through ``x``.
8. Positional MatchClass peel assumed Call-arg order equals ``__match_args__``,
   so reordered binders omitted client writes through the real state alias.

Unknown > false PASS. Held-out FormalPR partitions are not frozen.
"""

from __future__ import annotations

from ovk.compilers.authorization.bypass_authority import (
    AliasClassification,
    ClosedWorldScopeProof,
    _RequestStateAliasEnv,
    analyze_bypass_authority_unit,
    join_request_state_alias_envs,
)
from ovk.compilers.authorization.incremental_fastapi_compiler import (
    compile_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.persistent_fastapi_state import (
    PERSISTENT_FASTAPI_STATE_IMPLEMENTATION_VERSION,
    PersistentFastApiIncrementalStateCache,
    compile_persistent_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.python_ast_index import parse_head_python_materials
from ovk.compilers.authorization.fastapi_route_summary import build_route_summary_index
from ovk.compilers.authorization.resource_return_contracts import (
    build_contract_summary_index,
)
from ovk.compilers.authorization.semantic_summary_cache import (
    PersistentPythonSemanticSummaryCache,
)
from ovk.core.bundle import content_digest


def _scope(*paths: str, import_roots: tuple[str, ...] = ()) -> ClosedWorldScopeProof:
    return ClosedWorldScopeProof(
        accounted_paths=tuple(paths),
        source_roots=(".",),
        python_import_roots=import_roots,
    )


def _helpers_source(*, body: str = "True") -> str:
    return f"""
def write_state(state, value):
    state.bypass_filter = {body}
""".strip()


def _unit(routes: str, *, helpers: str | None = None) -> object:
    files = {
        "app/helpers.py": helpers or _helpers_source(),
        "app/routes.py": routes.strip(),
    }
    return analyze_bypass_authority_unit(
        files,
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope(
            "app/helpers.py",
            "app/routes.py",
            import_roots=("app",),
        ),
    )


def _safe_rebind_block(*, indent: int = 8, name: str = "write_state") -> str:
    pad = " " * indent
    return (
        f"{pad}def {name}(state, value):\n"
        f"{pad}    state.bypass_filter = True\n"
        f"{pad}helpers.write_state = {name}"
    )


def test_if_one_branch_severs_alias_other_writes_client_never_authorized() -> None:
    """1. Alias established; one if branch severs it, other writes client â†’ never authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    if bypass_filter:
        state = object()
    else:
        state.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_alias_on_one_branch_only_post_join_write_is_uncertain() -> None:
    """2. Alias established on only one branch; post-join field write â†’ uncertain/dynamic."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if bypass_filter:
        state = request.state
    state.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_alias_on_every_branch_may_remain_exact() -> None:
    """3. Alias established on every branch â†’ may remain exact / authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    if bypass_filter:
        state = request.state
    else:
        state = request.state
    state.bypass_filter = True
    return request.state.bypass_filter
"""
    )
    assert findings[0].status in {"authorized", "unknown"}
    if findings[0].status == "authorized":
        assert findings[0].reason == "source_proved_server_authority_write"


def test_try_body_severs_alias_handler_writes_through_original() -> None:
    """4. try body severs alias while handler writes through original alias."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    try:
        state = object()
    except Exception:
        state.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_handler_severs_alias_normal_path_writes_through_it() -> None:
    """5. Handler severs alias while normal path writes through it."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    try:
        state.bypass_filter = bypass_filter
    except Exception:
        state = object()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_match_pattern_binds_name_other_case_uses_prematch_alias() -> None:
    """6. match pattern binds same name in one case; other uses pre-match state alias."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, payload=None):
    state = request.state
    request.state.bypass_filter = True
    match payload:
        case {"state": state}:
            pass
        case _:
            state.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_guarded_wildcard_final_case_retains_nomatch_predecessor() -> None:
    """7. Guarded wildcard final ``case _ if cond`` retains no-match predecessor."""

    findings = _unit(
        f"""
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    match bypass_filter:
        case _ if bypass_filter:
{_safe_rebind_block(indent=12)}
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_unguarded_final_wildcard_still_exhaustive() -> None:
    """8. Unguarded final wildcard still exhaustive."""

    findings = _unit(
        f"""
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    match bypass_filter:
        case True:
{_safe_rebind_block(indent=12)}
        case _:
{_safe_rebind_block(indent=12)}
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status in {"authorized", "unknown"}
    if findings[0].status == "authorized":
        assert findings[0].reason == "source_proved_server_authority_write"


def test_guarded_irrefutable_safe_rebind_cannot_authorize_nomatch() -> None:
    """9. Guarded irrefutable safe rebind cannot authorize the no-match path."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    match bypass_filter:
        case _ if bypass_filter:
            def write_state(state, value):
                state.bypass_filter = True
            helpers.write_state = write_state
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_state_alias_write_inside_guarded_match_case_accounted() -> None:
    """10. State-alias write inside guarded match case is accounted."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    match bypass_filter:
        case _ if bypass_filter:
            state.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_loop_zero_iteration_join_preserves_may_alias() -> None:
    """11. Loop zero-iteration joins preserve may-alias state."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, items=None):
    state = request.state
    request.state.bypass_filter = True
    for _ in (items or []):
        state = object()
    state.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_alias_cf_full_equals_incremental() -> None:
    """12. full == incremental for alias CF / guarded-match cases."""

    trusted_helpers = """
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    clean_routes = """
from fastapi import Depends, FastAPI
import helpers
app = FastAPI()

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    helpers.write_state(request.state, True)
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip()
    poisoned_routes = """
from fastapi import Depends, FastAPI
import helpers
app = FastAPI()

def evil(state, value):
    state.bypass_filter = value

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user), payload=None):
    state = request.state
    request.state.bypass_filter = True
    if bypass_filter:
        state = object()
    else:
        state.bypass_filter = bypass_filter
    helpers.write_state = evil
    match bypass_filter:
        case _ if bypass_filter:
            def write_state(state, value):
                state.bypass_filter = True
            helpers.write_state = write_state
    helpers.write_state(request.state, bypass_filter)
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip()

    profile = FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_parameter="user",
    )

    def _materials(routes: str, revision: str) -> AuthMaterials:
        repo = {
            "app/helpers.py": trusted_helpers + "\n",
            "app/routes.py": routes,
        }
        return AuthMaterials(
            base_files=dict(repo),
            head_files=dict(repo),
            repo="example/request-state-alias-cf-joins",
            base_revision="base",
            head_revision=revision,
            repository_python_files=repo,
            head_repository_python_files=repo,
            base_repository_python_files=repo,
        )

    def _indexes(materials: AuthMaterials):
        parsed = parse_head_python_materials(materials)
        contracts = build_contract_summary_index(
            materials,
            parsed_trees=parsed.trees,
            source_digests=parsed.source_digests,
        )
        routes = build_route_summary_index(
            materials,
            parsed_trees=parsed.trees,
            source_digests=parsed.source_digests,
        )
        return parsed, contracts, routes

    first_materials = _materials(clean_routes, "head-1")
    parsed, contracts, routes = _indexes(first_materials)
    first = compile_incremental_fastapi_assurance(
        first_materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes,
    )
    first_payload = first.ir.canonical_payload()

    second_materials = _materials(poisoned_routes, "head-2")
    parsed2, contracts2, routes2 = _indexes(second_materials)
    second = compile_incremental_fastapi_assurance(
        second_materials,
        profile,
        parsed_index=parsed2,
        contract_summary_index=contracts2,
        route_summary_index=routes2,
        previous_state=first.state,
    )
    full = FastApiDependencyEffectExtractor().compile(
        second_materials,
        profile,
        parsed_index=parsed2,
        contract_summary_index=contracts2,
        route_summary_index=routes2,
    )
    assert second.ir.canonical_payload() == full.canonical_payload()
    assert second.ir.canonical_payload() != first_payload
    assert all(
        item.status != "established" for item in second.ir.bypass_authority_evidence
    )


def test_persistent_state_round_trip_and_version_invalidation(tmp_path) -> None:
    """13. Persistent-state round trip and version invalidation."""

    assert PERSISTENT_FASTAPI_STATE_IMPLEMENTATION_VERSION == "0.96.0"

    trusted_helpers = """
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    routes = """
from fastapi import Depends, FastAPI
import helpers
app = FastAPI()

@app.post("/chat")
async def handler(request, user = Depends(get_current_user)):
    helpers.write_state(request.state, True)
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip()
    repo = {
        "app/helpers.py": trusted_helpers + "\n",
        "app/routes.py": routes,
    }
    materials = AuthMaterials(
        base_files=dict(repo),
        head_files=dict(repo),
        repo="example/alias-cf-persistent",
        base_revision="base",
        head_revision="head-1",
        repository_python_files=repo,
        head_repository_python_files=repo,
        base_repository_python_files=repo,
    )
    profile = FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_parameter="user",
    )
    summary_root = tmp_path / "summaries"
    state_root = tmp_path / "state"
    state_cache = PersistentFastApiIncrementalStateCache(state_root)
    result = compile_persistent_incremental_fastapi_assurance(
        materials,
        profile,
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(summary_root),
        state_cache=state_cache,
    )
    state = result.compilation.state
    loaded = state_cache.get(
        repo=state.repo,
        profile_digest=state.profile_digest,
    )
    assert loaded is not None
    assert loaded.head_revision == state.head_revision

    cache_path = state_cache._path(
        repo=state.repo,
        profile_digest=state.profile_digest,
    )
    import json

    record = json.loads(cache_path.read_text(encoding="utf-8"))
    record["key_components"]["implementation_version"] = "0.37.0"
    record["key_digest"] = content_digest(record["key_components"])
    cache_path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert (
        state_cache.get(
            repo=state.repo,
            profile_digest=state.profile_digest,
        )
        is None
    )


def test_e2e_omitted_branch_write_cannot_source_proved_authorize() -> None:
    """14. End-to-end PE: omitted branch write must not yield source_proved_server_authority_write."""

    helpers = """
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    routes = """
from fastapi import Depends, FastAPI
import helpers
app = FastAPI()

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    state = request.state
    request.state.bypass_filter = True
    if bypass_filter:
        state = object()
    else:
        state.bypass_filter = bypass_filter
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip()
    repo = {
        "app/helpers.py": helpers + "\n",
        "app/routes.py": routes,
    }
    materials = AuthMaterials(
        base_files=dict(repo),
        head_files=dict(repo),
        repo="example/alias-cf-e2e",
        base_revision="base",
        head_revision="head",
        repository_python_files=repo,
        head_repository_python_files=repo,
        base_repository_python_files=repo,
    )
    profile = FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_parameter="user",
    )
    parsed = parse_head_python_materials(materials)
    contracts = build_contract_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    routes_idx = build_route_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    ir = FastApiDependencyEffectExtractor().compile(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes_idx,
    )
    assert all(
        item.status != "established" for item in ir.bypass_authority_evidence
    )
    for item in ir.bypass_authority_evidence:
        assert item.reason != "source_proved_server_authority_write"


def test_join_cross_kind_keeps_both_may_sets() -> None:
    """Cross-kind join retains the name in both may-request and may-state."""

    request_pred = _RequestStateAliasEnv(
        request_names={"x"},
        state_names=set(),
    )
    state_pred = _RequestStateAliasEnv(
        request_names=set(),
        state_names={"x"},
    )
    joined = join_request_state_alias_envs([request_pred, state_pred])
    assert "x" not in joined.request_names
    assert "x" not in joined.state_names
    assert "x" in joined.may_request_names
    assert "x" in joined.may_state_names

    import ast

    classification = joined.classify(ast.Name(id="x", ctx=ast.Load()))
    assert classification.may_request is True
    assert classification.may_state is True
    assert classification.must_request is False
    assert classification.must_state is False
    formal_env = _RequestStateAliasEnv(request_names=set(), state_names=set())
    formal_env.apply_classification("formal", classification)
    assert "formal" in formal_env.may_request_names
    assert "formal" in formal_env.may_state_names
    assert "formal" not in formal_env.request_names
    assert "formal" not in formal_env.state_names


def test_cross_kind_join_client_write_via_state_never_authorized() -> None:
    """1. Request on one branch, state on another, then x.field = client â†’ never authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if bypass_filter:
        x = request
    else:
        x = request.state
    x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_cross_kind_join_client_write_via_state_reversed_never_authorized() -> None:
    """2. Same as (1) with branch order reversed."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if bypass_filter:
        x = request.state
    else:
        x = request
    x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_cross_kind_join_request_state_field_write_is_dynamic() -> None:
    """3. Request on one branch, state on another, then x.state.field = client â†’ dynamic."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if bypass_filter:
        x = request
    else:
        x = request.state
    x.state.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_cross_kind_joined_alias_into_helper_never_authorized() -> None:
    """4. Cross-kind joined alias passed into a helper must not authorize."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if bypass_filter:
        x = request
    else:
        x = request.state
    helpers.write_state(x, True)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_may_state_actual_helper_literal_write_no_positive_authority() -> None:
    """5. May-state actual â†’ helper literal state write must NOT establish positive authority."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if bypass_filter:
        state = request.state
    helpers.write_state(state, True)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_may_request_actual_helper_state_attr_literal_no_positive_authority() -> None:
    """6. May-request actual â†’ helper req.state.field = literal must NOT establish positive authority."""

    findings = _unit(
        """
import helpers

def write_via_request(req, value):
    req.state.bypass_filter = value

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if bypass_filter:
        req = request
    write_via_request(req, True)
    return request.state.bypass_filter
""",
        helpers="""
def write_state(state, value):
    state.bypass_filter = True
""".strip(),
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_dual_may_actual_preserves_both_kinds_in_formal() -> None:
    """7. Actual in both may_request and may_state preserves both in formal."""

    findings = _unit(
        """
import helpers

def touch_both(x, value):
    x.bypass_filter = value
    x.state.bypass_filter = value

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if bypass_filter:
        x = request
    else:
        x = request.state
    touch_both(x, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_two_hop_helper_preserves_may_status() -> None:
    """8. Two-hop helper propagation preserves may status."""

    findings = _unit(
        """
import helpers

def inner(state, value):
    state.bypass_filter = value

def outer(state, value):
    inner(state, value)

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if bypass_filter:
        state = request.state
    outer(state, True)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_keyword_actual_formal_preserves_may_status() -> None:
    """9. Keyword actualâ†’formal preserves may status."""

    findings = _unit(
        """
import helpers

def write_state(*, state, value):
    state.bypass_filter = value

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if bypass_filter:
        st = request.state
    write_state(state=st, value=True)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_cross_kind_and_may_cases_via_setattr() -> None:
    """10. Same cross-kind / may-promotion cases using setattr."""

    findings_cross = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if bypass_filter:
        x = request
    else:
        x = request.state
    setattr(x, "bypass_filter", bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings_cross[0].status != "authorized"
    assert findings_cross[0].status in {"violated", "unknown"}

    findings_may = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if bypass_filter:
        state = request.state
    setattr(state, "bypass_filter", True)
    return request.state.bypass_filter
"""
    )
    assert findings_may[0].status != "authorized"
    assert findings_may[0].reason != "source_proved_server_authority_write"
    assert findings_may[0].status in {"violated", "unknown"}


def test_e2e_cross_kind_join_never_source_proved_authorize() -> None:
    """12. End-to-end PE: cross-kind counterexample never yields source_proved_server_authority_write."""

    helpers = """
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    routes = """
from fastapi import Depends, FastAPI
import helpers
app = FastAPI()

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    request.state.bypass_filter = True
    if bypass_filter:
        x = request
    else:
        x = request.state
    x.bypass_filter = bypass_filter
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip()
    repo = {
        "app/helpers.py": helpers + "\n",
        "app/routes.py": routes,
    }
    materials = AuthMaterials(
        base_files=dict(repo),
        head_files=dict(repo),
        repo="example/alias-cross-kind-e2e",
        base_revision="base",
        head_revision="head",
        repository_python_files=repo,
        head_repository_python_files=repo,
        base_repository_python_files=repo,
    )
    profile = FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_parameter="user",
    )
    parsed = parse_head_python_materials(materials)
    contracts = build_contract_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    routes_idx = build_route_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    ir = FastApiDependencyEffectExtractor().compile(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes_idx,
    )
    assert all(
        item.status != "established" for item in ir.bypass_authority_evidence
    )
    for item in ir.bypass_authority_evidence:
        assert item.reason != "source_proved_server_authority_write"

def test_cross_kind_full_equals_incremental() -> None:
    """11. full == incremental for the cross-kind alias join counterexample."""

    trusted_helpers = """
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    cross_kind_routes = """
from fastapi import Depends, FastAPI
import helpers
app = FastAPI()

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    request.state.bypass_filter = True
    if bypass_filter:
        x = request
    else:
        x = request.state
    x.bypass_filter = bypass_filter
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip()

    profile = FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_parameter="user",
    )
    repo = {
        "app/helpers.py": trusted_helpers + "\n",
        "app/routes.py": cross_kind_routes,
    }
    materials = AuthMaterials(
        base_files=dict(repo),
        head_files=dict(repo),
        repo="example/alias-cross-kind-incremental",
        base_revision="base",
        head_revision="head-1",
        repository_python_files=repo,
        head_repository_python_files=repo,
        base_repository_python_files=repo,
    )
    parsed = parse_head_python_materials(materials)
    contracts = build_contract_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    routes = build_route_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    incremental = compile_incremental_fastapi_assurance(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes,
    )
    full = FastApiDependencyEffectExtractor().compile(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes,
    )
    assert incremental.ir.canonical_payload() == full.canonical_payload()
    assert all(
        item.status != "established"
        for item in incremental.ir.bypass_authority_evidence
    )
    for item in incremental.ir.bypass_authority_evidence:
        assert item.reason != "source_proved_server_authority_write"


def test_ifexp_classify_cross_kind_keeps_dual_may() -> None:
    """IfExp arms of differing kind join to dual may (not poison)."""

    import ast

    env = _RequestStateAliasEnv.seed(param_names=frozenset({"request", "flag"}))
    tree = ast.parse("x = request.state if flag else request")
    assign = tree.body[0]
    assert isinstance(assign, ast.Assign)
    classification = env.classify(assign.value)
    assert classification.may_request is True
    assert classification.may_state is True
    assert classification.must_request is False
    assert classification.must_state is False
    env.note_binding(assign.targets[0], assign.value)
    assert "x" in env.may_request_names
    assert "x" in env.may_state_names
    assert "x" not in env.request_names
    assert "x" not in env.state_names

    same_kind = AliasClassification.join(
        AliasClassification(must_request=True),
        AliasClassification(must_request=True),
    )
    assert same_kind.must_request is True
    assert same_kind.may_request is False


def test_ifexp_cross_kind_client_write_never_authorized() -> None:
    """1. ``x = request.state if flag else request`` then ``x.field = client`` â†’ never authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    x = request.state if bypass_filter else request
    x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_ifexp_cross_kind_client_write_reversed_never_authorized() -> None:
    """2. Branch order reversed: ``x = request if flag else request.state`` â†’ same."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    x = request if bypass_filter else request.state
    x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_nested_ifexp_mixed_arms_dual_may_dynamic_write() -> None:
    """3. Nested IfExp with mixed request/state arms â†’ dual may / dynamic write."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, other=False):
    request.state.bypass_filter = True
    x = (request.state if bypass_filter else request) if other else request
    x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_ifexp_may_state_helper_literal_write_no_positive_authority() -> None:
    """4. IfExp may-state passed into helper literal write â†’ no positive authority."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    state = request.state if bypass_filter else request
    helpers.write_state(state, True)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_ifexp_may_request_then_state_field_write_is_dynamic() -> None:
    """5. IfExp may-request then ``x.state.field = client`` â†’ dynamic/UNKNOWN as applicable."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    x = request if bypass_filter else request.state
    x.state.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_walrus_ifexp_in_if_test_never_authorized() -> None:
    """Walrus + IfExp in ``if`` test must note dual-may before the body write."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if (x := (request.state if bypass_filter else request)):
        x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_annassign_ifexp_cross_kind_never_authorized() -> None:
    """AnnAssign with cross-kind IfExp RHS gets the same dual-may treatment."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    x: object = request.state if bypass_filter else request
    x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_ifexp_cross_kind_full_equals_incremental() -> None:
    """6. full == incremental for the IfExp cross-kind counterexample."""

    trusted_helpers = """
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    ifexp_routes = """
from fastapi import Depends, FastAPI
import helpers
app = FastAPI()

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    request.state.bypass_filter = True
    x = request.state if bypass_filter else request
    x.bypass_filter = bypass_filter
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip()

    profile = FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_parameter="user",
    )
    repo = {
        "app/helpers.py": trusted_helpers + "\n",
        "app/routes.py": ifexp_routes,
    }
    materials = AuthMaterials(
        base_files=dict(repo),
        head_files=dict(repo),
        repo="example/alias-ifexp-cross-kind-incremental",
        base_revision="base",
        head_revision="head-1",
        repository_python_files=repo,
        head_repository_python_files=repo,
        base_repository_python_files=repo,
    )
    parsed = parse_head_python_materials(materials)
    contracts = build_contract_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    routes = build_route_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    incremental = compile_incremental_fastapi_assurance(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes,
    )
    full = FastApiDependencyEffectExtractor().compile(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes,
    )
    assert incremental.ir.canonical_payload() == full.canonical_payload()
    assert all(
        item.status != "established"
        for item in incremental.ir.bypass_authority_evidence
    )
    for item in incremental.ir.bypass_authority_evidence:
        assert item.reason != "source_proved_server_authority_write"


def test_e2e_ifexp_cross_kind_never_source_proved_authorize() -> None:
    """7. End-to-end PE regression for the IfExp counterexample."""

    helpers = """
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    routes = """
from fastapi import Depends, FastAPI
import helpers
app = FastAPI()

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    request.state.bypass_filter = True
    x = request.state if bypass_filter else request
    x.bypass_filter = bypass_filter
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip()
    repo = {
        "app/helpers.py": helpers + "\n",
        "app/routes.py": routes,
    }
    materials = AuthMaterials(
        base_files=dict(repo),
        head_files=dict(repo),
        repo="example/alias-ifexp-cross-kind-e2e",
        base_revision="base",
        head_revision="head",
        repository_python_files=repo,
        head_repository_python_files=repo,
        base_repository_python_files=repo,
    )
    profile = FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_parameter="user",
    )
    parsed = parse_head_python_materials(materials)
    contracts = build_contract_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    routes_idx = build_route_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    ir = FastApiDependencyEffectExtractor().compile(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes_idx,
    )
    assert all(
        item.status != "established" for item in ir.bypass_authority_evidence
    )
    for item in ir.bypass_authority_evidence:
        assert item.reason != "source_proved_server_authority_write"


def test_boolop_and_or_cross_kind_never_authorized() -> None:
    """BoolOp ``flag and request.state or request`` joins to dual may â€” never PASS."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, flag=True):
    request.state.bypass_filter = True
    x = flag and request.state or request
    x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_boolop_same_kind_and_or_never_authorized() -> None:
    """Same-kind BoolOp still yields may (short-circuit) â€” never PASS."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, flag=True):
    request.state.bypass_filter = True
    x = flag and request.state or request.state
    x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_boolop_classify_lattice_units() -> None:
    """Unit: BoolOp classify joins operands; never promotes mayâ†’must."""

    import ast

    env = _RequestStateAliasEnv.seed(param_names=frozenset({"request", "flag"}))
    cross = env.classify(ast.parse("flag and request.state or request").body[0].value)
    assert cross == AliasClassification(
        must_request=False,
        may_request=True,
        must_state=False,
        may_state=True,
    )
    and_only = env.classify(ast.parse("flag and request.state").body[0].value)
    assert and_only == AliasClassification(
        must_request=False,
        may_request=False,
        must_state=False,
        may_state=True,
    )
    state_or_none = env.classify(ast.parse("request.state or None").body[0].value)
    assert state_or_none == AliasClassification(
        must_request=False,
        may_request=False,
        must_state=False,
        may_state=True,
    )


def test_match_as_pattern_captures_state_subject_never_authorized() -> None:
    """``match request.state: case object() as x:`` binds x â€” never false PASS."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    match request.state:
        case object() as x:
            x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_match_irrefutable_name_binds_state_subject() -> None:
    """``case x:`` on a state subject captures state identity."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    match request.state:
        case x:
            x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_match_sequence_peel_state_element_never_authorized() -> None:
    """``match [request.state]: case [x]:`` peels the element alias."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    match [request.state]:
        case [x]:
            x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_match_mapping_peel_state_value_never_authorized() -> None:
    """``match {'s': request.state}: case {'s': x}:`` peels the value alias."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    match {"s": request.state}:
        case {"s": x}:
            x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_match_guard_walrus_binds_state_never_authorized() -> None:
    """Walrus in a match guard notes state identity before the body write."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    match bypass_filter:
        case _ if (x := request.state):
            x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_walrus_boolop_in_if_test_never_authorized() -> None:
    """Walrus + BoolOp in ``if`` test notes dual-may before the body write."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, flag=True):
    request.state.bypass_filter = True
    if (x := (flag and request.state or request)):
        x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_interprocedural_boolop_dual_may_no_positive_authority() -> None:
    """BoolOp dual-may into a helper literal write â†’ no positive authority."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, flag=True):
    request.state.bypass_filter = True
    x = flag and request.state or request
    helpers.write_state(x, True)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_with_nullcontext_state_as_target_never_authorized() -> None:
    """``with nullcontext(request.state) as x`` may-binds enter result."""

    findings = _unit(
        """
import helpers
from contextlib import nullcontext
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    with nullcontext(request.state) as x:
        x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_matchclass_positional_peel_match_args_reorder_never_authorized() -> None:
    """Positional MatchClass must not 1:1-peel Call args (``__match_args__`` reorder).

    ``Pair.__match_args__ = ("second", "first")`` makes ``case Pair(x, _)`` bind
    ``x`` to ``second`` (= ``request.state``) while Call order is
    ``(object(), request.state)``. A 1:1 positional peel bound ``x`` to
    ``object()`` and omitted the client write â†’ false PASS.
    """

    findings = _unit(
        """
import helpers
class Pair:
    __match_args__ = ("second", "first")
    def __init__(self, first, second):
        self.first = first
        self.second = second
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    match Pair(object(), request.state):
        case Pair(x, _):
            x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_matchclass_positional_default_order_still_accounts_client_write() -> None:
    """Even when Call order matches default attrs, positional peel is refused."""

    findings = _unit(
        """
import helpers
class Box:
    def __init__(self, a, b):
        self.a = a
        self.b = b
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    match Box(request.state, object()):
        case Box(x, _):
            x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_matchclass_keyword_peel_accounts_client_write() -> None:
    """Keyword-only MatchClass vs keyword Call remains a sound peel/may path."""

    findings = _unit(
        """
import helpers
class Box:
    def __init__(self, a, b):
        self.a = a
        self.b = b
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    match Box(a=object(), b=request.state):
        case Box(b=x):
            x.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_boolop_full_equals_incremental() -> None:
    """full == incremental for the BoolOp cross-kind counterexample."""

    trusted_helpers = """
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    boolop_routes = """
from fastapi import Depends, FastAPI
import helpers
app = FastAPI()

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    request.state.bypass_filter = True
    x = bypass_filter and request.state or request
    x.bypass_filter = bypass_filter
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip()

    profile = FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_parameter="user",
    )
    repo = {
        "app/helpers.py": trusted_helpers + "\n",
        "app/routes.py": boolop_routes,
    }
    materials = AuthMaterials(
        base_files=dict(repo),
        head_files=dict(repo),
        repo="example/alias-boolop-cross-kind-incremental",
        base_revision="base",
        head_revision="head-1",
        repository_python_files=repo,
        head_repository_python_files=repo,
        base_repository_python_files=repo,
    )
    parsed = parse_head_python_materials(materials)
    contracts = build_contract_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    routes = build_route_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    incremental = compile_incremental_fastapi_assurance(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes,
    )
    full = FastApiDependencyEffectExtractor().compile(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes,
    )
    assert incremental.ir.canonical_payload() == full.canonical_payload()
    assert all(
        item.status != "established"
        for item in incremental.ir.bypass_authority_evidence
    )
    for item in incremental.ir.bypass_authority_evidence:
        assert item.reason != "source_proved_server_authority_write"


def test_for_else_from_pre_loop_env_never_authorized() -> None:
    """for-else walks from pre-loop env so body-mutated aliases cannot drop writes."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = request.state
    for _ in [1]:
        s = object()
    else:
        s.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_for_iter_boolop_packing_never_authorized() -> None:
    """For-iter BoolOp packing of ``[request.state]`` counts body writes."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, flag=True):
    request.state.bypass_filter = True
    for s in (flag and [request.state] or [request.state]):
        s.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_ifexp_request_dot_state_write_never_authorized() -> None:
    """``(request if f else request).state.field = client`` is counted."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, flag=True):
    request.state.bypass_filter = True
    (request if flag else request).state.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_getattr_boolop_request_state_write_never_authorized() -> None:
    """``getattr(flag and request or request, "state").field = client``."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, flag=True):
    request.state.bypass_filter = True
    getattr(flag and request or request, "state").bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_subscript_projection_state_write_never_authorized() -> None:
    """``[request.state][0].field = client`` is may-alias / dynamic, not omitted."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    [request.state][0].bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_list_set_projection_state_write_never_authorized() -> None:
    """``list({request.state})[0].field = client`` must not omit the write."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    list({request.state})[0].bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_dict_values_projection_state_write_never_authorized() -> None:
    """``list({\"k\": request.state}.values())[0].field = client`` residual."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    list({"k": request.state}.values())[0].bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_next_iter_dict_values_write_never_authorized() -> None:
    """``next(iter({\"a\": request.state}.values())).field = client`` residual."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    next(iter({"a": request.state}.values())).bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_for_dict_values_inline_never_authorized() -> None:
    """``for s in {\"k\": request.state}.values():`` must escape / count writes."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    for s in {"k": request.state}.values():
        s.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_for_module_generator_packing_never_authorized() -> None:
    """Module-level generator yielding packed request.state must not authorize."""

    findings = _unit(
        """
import helpers
def gen(items):
    for x in items:
        yield x
def handler(request, bypass_filter=False, flag=True):
    request.state.bypass_filter = True
    for s in gen([request.state] if flag else [request.state]):
        s.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_async_for_module_generator_packing_never_authorized() -> None:
    """Async module-level generator packing request.state must not authorize."""

    findings = _unit(
        """
import helpers
async def agen(items):
    for x in items:
        yield x
async def handler(request, bypass_filter=False, flag=True):
    request.state.bypass_filter = True
    async for s in agen(flag and [request.state] or [request.state]):
        s.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_try_finally_no_handler_joins_exceptional_predecessor() -> None:
    """try/finally with no handler joins exceptional pred before finally."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    try:
        helpers.write_state = evil
        raise ValueError()
    finally:
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_ifexp_subscript_store_after_trusted_never_authorized() -> None:
    """Subscript store on IfExp state base must use classify() like attrs."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, flag=True):
    request.state.bypass_filter = True
    (request.state if flag else request)["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_boolop_subscript_store_after_trusted_never_authorized() -> None:
    """Subscript store on BoolOp state base must not omit the client write."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, flag=True):
    request.state.bypass_filter = True
    (flag and request.state)["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_namedexpr_subscript_store_after_trusted_never_authorized() -> None:
    """Subscript store on NamedExpr state base must not omit the client write."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    (s := request.state)["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_dict_get_projection_write_never_authorized() -> None:
    """``{\"s\": request.state}.get(\"s\").field = client`` must not authorize."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = {"s": request.state}.get("s")
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_dict_pop_projection_write_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = {"s": request.state}.pop("s")
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_operator_getitem_projection_write_never_authorized() -> None:
    findings = _unit(
        """
import helpers
import operator
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = operator.getitem({"s": request.state}, "s")
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_itemgetter_projection_write_never_authorized() -> None:
    findings = _unit(
        """
import helpers
import operator
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = operator.itemgetter("s")({"s": request.state})
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_alias_lattice_projection_variants_never_authorized() -> None:
    """Unbound/aliased dict/operator/MappingProxyType/| projections."""

    for routes in (
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = dict.get({"s": request.state}, "s")
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
from operator import itemgetter
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = itemgetter("s")({"s": request.state})
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
import operator as op
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = op.itemgetter("s")({"s": request.state})
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = dict.__getitem__({"s": request.state}, "s")
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = getattr({"s": request.state}, "get")("s")
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    k, s = {"s": request.state}.popitem()
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = operator.methodcaller("get", "s")({"s": request.state})
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
from types import MappingProxyType
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = MappingProxyType({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = ({} | {"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
import types
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = types.MappingProxyType({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
import types as t
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = t.MappingProxyType({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
from types import MappingProxyType as MPT
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = MPT({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
from operator import getitem as gi
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = gi({"s": request.state}, "s")
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
from operator import itemgetter as ig
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = ig("s")({"s": request.state})
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
        """
import helpers
from operator import methodcaller as mc
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    s = mc("get", "s")({"s": request.state})
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"
        assert findings[0].status in {"violated", "unknown"}
