"""Request/state alias CF joins + guarded match exhaustiveness (#171).

Closes false PASSes where:
1. Guarded final ``case _ if cond:`` was treated as exhaustive.
2. A shared mutable request/state alias env let one CF branch erase
   aliases before another branch's client write was scanned.

Unknown > false PASS. Held-out FormalPR partitions are not frozen.
"""

from __future__ import annotations

from ovk.compilers.authorization.bypass_authority import (
    ClosedWorldScopeProof,
    analyze_bypass_authority_unit,
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
    """1. Alias established; one if branch severs it, other writes client → never authorized."""

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
    """2. Alias established on only one branch; post-join field write → uncertain/dynamic."""

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
    """3. Alias established on every branch → may remain exact / authorized."""

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

    assert PERSISTENT_FASTAPI_STATE_IMPLEMENTATION_VERSION == "0.36.0"

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
    record["key_components"]["implementation_version"] = "0.35.0"
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
