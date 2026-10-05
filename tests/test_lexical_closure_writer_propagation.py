"""Bounded lexical-environment propagation for state-writer callees (#173).

Nested closures / default captures of request/state aliases must enter the
writer theorem at call time. Definition-time body scans under an empty alias
seed omit zero-argument closure writes and false-PASS beside a trusted literal.

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


def _never_authorized(findings: object) -> None:
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}
    assert findings[0].reason != "source_proved_server_authority_write"


def test_zero_arg_closure_captures_state_alias_never_authorized() -> None:
    """1. Zero-arg nested closure captures state = request.state → never authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True

    def poison():
        state.bypass_filter = bypass_filter

    poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_closure_captures_request_alias_writes_state_field() -> None:
    """2. Closure captures req = request and writes req.state.field → never authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    req = request
    request.state.bypass_filter = True

    def poison():
        req.state.bypass_filter = bypass_filter

    poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_closure_captures_outer_request_and_client_input() -> None:
    """3. Closure directly captures outer request and client input."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True

    def poison():
        request.state.bypass_filter = bypass_filter

    poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_closure_may_state_alias_from_branch_join_dynamic() -> None:
    """4. Closure captures may-state alias from branch join → dynamic/UNKNOWN."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, flag=False):
    request.state.bypass_filter = True
    if flag:
        state = request.state
    else:
        state = object()

    def poison():
        state.bypass_filter = bypass_filter

    poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_closure_alias_rebound_before_call_uses_call_time_env() -> None:
    """5. Closure alias rebound before call; call-time env determines identity."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = object()
    request.state.bypass_filter = True

    def poison():
        state.bypass_filter = bypass_filter

    state = request.state
    poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_closure_late_binding_after_definition() -> None:
    """6. Alias becomes governed only after def; late binding sees it at call."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True

    def poison():
        state.bypass_filter = bypass_filter

    state = request.state
    poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_default_param_state_omitted_at_call_counted() -> None:
    """7. Default parameter state=request.state, omitted at call → writer counted."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True

    def poison(state=request.state):
        state.bypass_filter = bypass_filter

    poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_default_param_explicitly_overridden_unrelated_object() -> None:
    """8. Default overridden with unrelated object → default identity does not apply.

    With an unrelated explicit actual, the nested write is not a governed-state
    write. Authority may still fail closed for other reasons; the trusted
    literal alone must not authorize when a client write remains elsewhere —
    here the only client write target is non-state, so a pure trusted path
    may authorize. Guard: overridden default must not be treated as state.
    """

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    other = object()

    def poison(state=request.state):
        state.bypass_filter = bypass_filter

    poison(other)
    return request.state.bypass_filter
"""
    )
    # No governed client write remains; trusted literal may authorize.
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_default_captured_before_outer_alias_rebind() -> None:
    """9. Default captured before outer alias rebind → definition-time identity."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True

    def poison(target=state):
        target.bypass_filter = bypass_filter

    state = object()
    poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_two_nested_call_levels_preserve_closure_alias() -> None:
    """10. Two nested call levels preserve closure alias/provenance."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True

    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        poison()

    mid()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_keyword_default_combination_preserves_must_may() -> None:
    """11. Keyword/default combinations preserve must/may strength."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, flag=False):
    request.state.bypass_filter = True
    if flag:
        x = request.state
    else:
        x = object()

    def poison(target=x):
        target.bypass_filter = bypass_filter

    poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_nested_async_function_closure() -> None:
    """12. Nested async function closure."""

    findings = _unit(
        """
import helpers
async def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True

    async def poison():
        state.bypass_filter = bypass_filter

    await poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_nested_lambda_closure_mutates_governed_state() -> None:
    """13. Nested lambda closure that mutates governed state."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    poison = lambda: setattr(state, "bypass_filter", bypass_filter)
    poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_escaped_closure_carrying_governed_state_unknown() -> None:
    """14. Escaped closure carrying governed state identity → UNKNOWN."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True

    def poison():
        state.bypass_filter = bypass_filter

    return poison
"""
    )
    _never_authorized(findings)


def test_full_equals_incremental_closure_counterexample() -> None:
    """15. Full compilation == incremental compilation for closure case."""

    trusted_helpers = _helpers_source()
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

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    state = request.state
    request.state.bypass_filter = True
    def poison():
        state.bypass_filter = bypass_filter
    poison()
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
            repo="example/lexical-closure-writer-propagation",
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


def test_e2e_pe_no_established_bypass_for_closure_counterexample() -> None:
    """16. End-to-end PE: first counterexample never yields established bypass."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True

    def poison():
        state.bypass_filter = bypass_filter

    poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)
    assert "source_proved" not in findings[0].reason


def test_class_nested_method_closes_over_state_never_authorized() -> None:
    """Class-nested method closing over outer state and called → never authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    class Box:
        def poison(self):
            state.bypass_filter = bypass_filter
    Box().poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_list_subscript_closure_call_never_authorized() -> None:
    """Closure assigned to list and called via subscript → never authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def poison():
        state.bypass_filter = bypass_filter
    bucket = [poison]
    bucket[0]()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_dict_subscript_closure_call_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def poison():
        state.bypass_filter = bypass_filter
    m = {"p": poison}
    m["p"]()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_getattr_class_method_closure_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    class Box:
        def poison(self):
            state.bypass_filter = bypass_filter
    getattr(Box(), "poison")()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_ifexp_packed_closure_callee_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def poison():
        state.bypass_filter = bypass_filter
    def noop():
        pass
    (poison if True else noop)()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_attr_store_closure_then_call_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def poison():
        state.bypass_filter = bypass_filter
    class Holder:
        pass
    h = Holder()
    h.fn = poison
    h.fn()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_list_append_closure_then_call_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def poison():
        state.bypass_filter = bypass_filter
    bucket = []
    bucket.append(poison)
    bucket[0]()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_returned_closure_name_call_never_authorized() -> None:
    """``fn = mid(); fn()`` where mid returns a free-var closure → never authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    fn = mid()
    fn()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_cell_rebind_between_mid_return_and_call_never_authorized() -> None:
    """Late-bound cell becomes governed after mid returns poison → never authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, flag=False):
    state = object()
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    fn = mid()
    if flag:
        state = request.state
    else:
        state = request.state
    fn()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_walrus_bound_returned_closure_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def _make():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    if (fn := _make()):
        fn()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_map_higher_order_closure_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def poison(_):
        state.bypass_filter = bypass_filter
    list(map(poison, [0]))
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_methodcaller_higher_order_closure_never_authorized() -> None:
    findings = _unit(
        """
import helpers
import operator
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def poison():
        state.bypass_filter = bypass_filter
    mc = operator.methodcaller("__call__")
    mc(poison)
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_nonlocal_rebind_then_nested_write_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = object()
    request.state.bypass_filter = True
    def mid():
        nonlocal state
        state = request.state
        def poison():
            state.bypass_filter = bypass_filter
        poison()
    mid()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_inline_list_packed_closure_call_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def poison():
        state.bypass_filter = bypass_filter
    [poison][0]()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_bare_async_closure_call_does_not_execute_body() -> None:
    """Bare Call of async def builds a coroutine; body writers must not fire."""

    findings = _unit(
        """
import helpers
async def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True

    async def poison():
        state.bypass_filter = bypass_filter

    poison()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_await_async_closure_still_counts_body_writers() -> None:
    """``await poison()`` must still observe async closure body writers."""

    findings = _unit(
        """
import helpers
async def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True

    async def poison():
        state.bypass_filter = bypass_filter

    await poison()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_await_name_bound_async_coro_still_counts() -> None:
    """``coro = poison(); await coro`` follows the async body via Name capture."""

    findings = _unit(
        """
import helpers
async def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True

    async def poison():
        state.bypass_filter = bypass_filter

    coro = poison()
    await coro
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_unused_async_def_trusted_path_still_authorizes() -> None:
    """Trusted path with an unused async def (never called) still authorizes."""

    findings = _unit(
        """
import helpers
async def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True

    async def poison():
        state.bypass_filter = bypass_filter

    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_returned_closure_unused_binding_still_authorizes() -> None:
    """``fn = mid()`` without ``fn()`` must not blanket-escape the return."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    fn = mid()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_returned_closure_name_call_precise_follow_never_authorized() -> None:
    """Precise ``fn = mid(); fn()`` follow (not escape-only) never authorizes."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    fn = mid()
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_returned_closure_mid_local_cell_never_authorized() -> None:
    """Capture mid-frame locals at return; follow at ``fn()`` with that env."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    def mid():
        local_state = request.state
        def poison():
            local_state.bypass_filter = bypass_filter
        return poison
    fn = mid()
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_returned_closure_dunder_call_never_authorized() -> None:
    """``fn.__call__()`` after ``fn = mid()`` must follow the returned closure."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    fn = mid()
    fn.__call__()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_returned_closure_rebind_to_noop_still_authorizes() -> None:
    """Rebinding ``fn`` away from a returned closure must drop the capture."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    def noop():
        pass
    fn = mid()
    fn = noop
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_async_for_async_gen_body_never_authorized() -> None:
    """AsyncFor entry executes async generator bodies (not bare Call)."""

    findings = _unit(
        """
import helpers
async def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    async def agen():
        state.bypass_filter = bypass_filter
        yield 1
    async for x in agen():
        pass
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_getattr_call_on_returned_closure_never_authorized() -> None:
    """``getattr(fn, \"__call__\")()`` after ``fn = mid()`` never authorizes."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    fn = mid()
    getattr(fn, "__call__")()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_returned_callable_class_instance_never_authorized() -> None:
    """``fn = mid(); fn()`` when mid returns governed ``Cls()`` never authorizes."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        class Box:
            def __call__(self):
                state.bypass_filter = bypass_filter
        return Box()
    fn = mid()
    fn()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_async_with_local_aenter_never_authorized() -> None:
    """AsyncWith entry follows local class ``__aenter__`` body writers."""

    findings = _unit(
        """
import helpers
async def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    class CM:
        async def __aenter__(self):
            state.bypass_filter = bypass_filter
            return self
        async def __aexit__(self, *a):
            return False
    async with CM():
        pass
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_ifexp_assign_returned_closure_never_authorized() -> None:
    """``fn = mid() if c else noop; fn()`` dual-may follows poison arm."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, c=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    def noop():
        pass
    fn = mid() if c else noop
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_boolop_assign_returned_closure_never_authorized() -> None:
    """``fn = mid() or noop; fn()`` dual-may follows poison arm."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    def noop():
        pass
    fn = mid() or noop
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_ifexp_unknown_arm_call_never_authorized() -> None:
    """Unknown IfExp callable arm must fail closed on later ``fn()``."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, c=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    fn = mid() if c else unknown
    fn()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_ifexp_both_unknown_arms_call_never_authorized() -> None:
    """``fn = unknown if c else other; fn()`` must not authorize."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, c=False):
    request.state.bypass_filter = True
    fn = unknown if c else other
    fn()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_stmt_if_join_returned_closure_never_authorized() -> None:
    """Statement ``if`` join of ``fn = mid()`` / ``fn = noop`` keeps poison arm."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, c=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    def noop():
        pass
    if c:
        fn = mid()
    else:
        fn = noop
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_mid_ifexp_return_never_authorized() -> None:
    """``return poison if c else noop`` from mid dual-may joins at ``fn()``."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, c=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        def noop():
            pass
        return poison if c else noop
    fn = mid()
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_nested_factory_return_name_never_authorized() -> None:
    """``return mid`` factory product must follow through ``mid_fn(); fn()``."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def outer():
        def mid():
            def poison():
                state.bypass_filter = bypass_filter
            return poison
        return mid
    mid_fn = outer()
    fn = mid_fn()
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_chained_call_product_never_authorized() -> None:
    """``fn = outer()(); fn()`` follows nested returned closures."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def outer():
        def mid():
            def poison():
                state.bypass_filter = bypass_filter
            return poison
        return mid
    fn = outer()()
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_list_packed_mid_product_never_authorized() -> None:
    """``box = [mid()]; box[0]()`` must not authorize (packing escape)."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    box = [mid()]
    box[0]()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_attr_packed_mid_product_never_authorized() -> None:
    """``box.fn = mid(); box.fn()`` must not authorize."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    class Box:
        pass
    box = Box()
    box.fn = mid()
    box.fn()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_functools_partial_returned_closure_never_authorized() -> None:
    findings = _unit(
        """
import helpers
import functools
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    fn = mid()
    functools.partial(fn)()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_starargs_returned_closure_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    fn = mid()
    args = ()
    fn(*args)
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_kwargs_returned_closure_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    fn = mid()
    kwargs = {}
    fn(**kwargs)
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_asyncio_create_task_closure_never_authorized() -> None:
    findings = _unit(
        """
import helpers
import asyncio
async def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    async def poison():
        state.bypass_filter = bypass_filter
    asyncio.create_task(poison())
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_asyncio_ensure_future_closure_never_authorized() -> None:
    findings = _unit(
        """
import helpers
import asyncio
async def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    async def poison():
        state.bypass_filter = bypass_filter
    asyncio.ensure_future(poison())
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_asyncio_taskgroup_closure_never_authorized() -> None:
    findings = _unit(
        """
import helpers
import asyncio
async def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    async def poison():
        state.bypass_filter = bypass_filter
    async with asyncio.TaskGroup() as tg:
        tg.create_task(poison())
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_try_except_returned_closure_join_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    def noop():
        pass
    try:
        fn = mid()
    except Exception:
        fn = noop
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_match_returned_closure_join_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, c=0):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    def noop():
        pass
    match c:
        case 1:
            fn = mid()
        case _:
            fn = noop
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_walrus_ifexp_returned_closure_never_authorized() -> None:
    """``if (fn := (mid() if c else noop)): fn()`` must not authorize."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, c=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    def noop():
        pass
    if (fn := (mid() if c else noop)):
        fn()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_unused_ifexp_returned_closure_still_authorizes() -> None:
    """Unused ``fn = mid() if c else noop`` must not blanket-escape."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, c=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    def noop():
        pass
    fn = mid() if c else noop
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_overridden_default_unrelated_object_still_authorizes() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid(cell=request.state):
        def poison():
            cell.bypass_filter = bypass_filter
        return poison
    fn = mid(object())
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_match_case_as_binds_returned_closure_never_authorized() -> None:
    """``match mid(): case fn: fn()`` must follow the subject product."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    match mid():
        case fn:
            fn()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_with_enter_returns_closure_never_authorized() -> None:
    """``with CM() as fn`` when ``__enter__`` returns a governed closure."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    class CM:
        def __enter__(self):
            def poison():
                state.bypass_filter = bypass_filter
            return poison
        def __exit__(self, *a):
            return False
    with CM() as fn:
        fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_with_enter_returns_mid_product_never_authorized() -> None:
    """``__enter__`` returning ``mid()`` must resolve outer nested callables."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    def mid():
        def poison():
            state.bypass_filter = bypass_filter
        return poison
    class CM:
        def __enter__(self):
            return mid()
        def __exit__(self, *a):
            return False
    with CM() as fn:
        fn()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_async_with_aenter_returns_closure_never_authorized() -> None:
    findings = _unit(
        """
import helpers
async def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    class CM:
        async def __aenter__(self):
            def poison():
                state.bypass_filter = bypass_filter
            return poison
        async def __aexit__(self, *a):
            return False
    async with CM() as fn:
        fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_outer_frame_cls_call_instance_never_authorized() -> None:
    """Handler-local ``Cls(); obj()`` must follow governed ``__call__``."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    class Cls:
        def __call__(self):
            state.bypass_filter = bypass_filter
    obj = Cls()
    obj()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_outer_frame_cls_via_mid_return_never_authorized() -> None:
    """``return Cls()`` from mid must see enclosing local classes."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    class Cls:
        def __call__(self):
            state.bypass_filter = bypass_filter
    def mid():
        return Cls()
    fn = mid()
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_chained_cls_call_never_authorized() -> None:
    """``Cls()()`` must follow the constructor's governed ``__call__``."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    class Cls:
        def __call__(self):
            state.bypass_filter = bypass_filter
    Cls()()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_classmethod_factory_returned_closure_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    class Cls:
        @classmethod
        def make(cls):
            def poison():
                state.bypass_filter = bypass_filter
            return poison
    fn = Cls.make()
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_staticmethod_factory_returned_closure_never_authorized() -> None:
    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    class Cls:
        @staticmethod
        def make():
            def poison():
                state.bypass_filter = bypass_filter
            return poison
    fn = Cls.make()
    fn()
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_operator_call_cls_instance_never_authorized() -> None:
    findings = _unit(
        """
import helpers
import operator
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    class Cls:
        def __call__(self):
            state.bypass_filter = bypass_filter
    operator.call(Cls())
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_typing_cast_cls_instance_never_authorized() -> None:
    findings = _unit(
        """
import helpers
import typing
def handler(request, bypass_filter=False):
    state = request.state
    request.state.bypass_filter = True
    class Cls:
        def __call__(self):
            state.bypass_filter = bypass_filter
    fn = typing.cast(object, Cls())
    fn()
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_init_attr_pack_closure_call_never_authorized() -> None:
    """``Box().__init__`` packs ``self.fn = poison`` then ``Box().fn()``."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    Box().fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_property_returned_closure_call_never_authorized() -> None:
    """``@property`` returning a governed callable then call must not authorize."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        @property
        def fn(self):
            return poison
    Box().fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_cached_property_returned_closure_call_never_authorized() -> None:
    """``@cached_property`` returning a governed callable then call."""

    findings = _unit(
        """
import helpers
from functools import cached_property
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        @cached_property
        def fn(self):
            return poison
    Box().fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_decorator_rebinds_name_to_poison_never_authorized() -> None:
    """``@deco`` returning inline poison must rebind the def Name."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    def deco(f):
        return poison
    @deco
    def fn():
        pass
    fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_instance_alias_and_getattr_init_pack_never_authorized() -> None:
    """``b=Box(); b.fn()`` / ``getattr(Box(),\"fn\")()`` after init pack."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    b = Box()
    b.fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    getattr(Box(), "fn")()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    _never_authorized(findings)


def test_setattr_cf_new_classbody_property_packs_never_authorized() -> None:
    """setattr/CF/__new__/class-body/property packing must not authorize."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            setattr(self, "fn", poison)
    Box().fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            if True:
                self.fn = poison
    Box().fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __new__(cls):
            obj = object.__new__(cls)
            obj.fn = poison
            return obj
    Box().fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        fn = poison
    Box().fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        @property
        def fn(self):
            return poison
    f = Box().fn
    f()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    def _fn(self):
        return poison
    class Box:
        fn = property(_fn)
    Box().fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        _never_authorized(_unit(routes))


def test_third_pass_lexical_packing_shapes_never_authorized() -> None:
    """Name-bound getattr, double alias, inherited init, property/getattr packs."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    g = getattr
    g(Box(), "fn")()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    b = Box()
    c = b
    c.fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Base:
        def __init__(self):
            self.fn = poison
    class Child(Base):
        pass
    Child().fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        @property
        def fn(self):
            return poison
    getattr(Box(), "fn")()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    [Box()][0].fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    (Box() if True else Box()).fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        pass
    getattr(Box(), "missing", poison)()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        _never_authorized(_unit(routes))


def test_fourth_pass_lexical_inherited_property_and_packs_never_authorized() -> None:
    """Inherited @property, Name-bound packs, nested walrus, itemgetter peel."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Base:
        @property
        def fn(self):
            return poison
    class Child(Base):
        pass
    Child().fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    xs=[Box()]
    xs[0].fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    c = True
    x=Box() if c else Box()
    x.fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    if (c:=(b:=Box())):
        c.fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    operator.itemgetter(0)([Box()]).fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    n = "fn"
    getattr(Box(), n)()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    match Box():
        case b:
            b.fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    [x.fn() for x in [Box()]]
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import builtins
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    builtins.getattr(Box(), "fn")()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    operator.attrgetter("fn")(Box())()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        _never_authorized(_unit(routes))


def test_fifth_pass_name_bound_attrgetter_product_never_authorized() -> None:
    """``ag = attrgetter(\"fn\"); ag(Box())()`` must follow the packed writer."""

    _never_authorized(
        _unit(
            """
import helpers
from operator import attrgetter as agf
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    ag = agf("fn")
    ag(Box())()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        )
    )


def test_sixth_pass_instance_carrier_seeds_never_authorized() -> None:
    """For/match/with instance seeds + Name-bound class constructor ``__call__``."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    match [Box()]:
        case [b]:
            b.fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    match {"x": Box()}:
        case {"x": b}:
            b.fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    for x in [Box()]:
        x.fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    xs = [Box()]
    for x in xs:
        x.fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    class Box:
        def __init__(self):
            self.fn = poison
    class CM:
        def __enter__(self):
            return Box()
        def __exit__(self, *a):
            return False
    with CM() as b:
        b.fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Cls:
        def __call__(self):
            helpers.write_state = evil
    C = Cls
    C()()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Cls:
        def __call__(self):
            helpers.write_state = evil
    C = Cls
    obj = C()
    obj()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Cls:
        def __call__(self):
            helpers.write_state = evil
    (C := Cls)()()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        _never_authorized(_unit(routes))


def test_seventh_pass_packed_class_constructor_seeds_never_authorized() -> None:
    """Packed class aliases + For/with constructor seeds observe ``__call__``."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Cls:
        def __call__(self):
            helpers.write_state = evil
    C = [Cls][0]
    C()()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Cls:
        def __call__(self):
            helpers.write_state = evil
    tmp = [Cls][0]
    C = tmp
    C()()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Cls:
        def __call__(self):
            helpers.write_state = evil
    for C in [Cls]:
        C()()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Cls:
        def __call__(self):
            helpers.write_state = evil
    class CM:
        def __enter__(self):
            return Cls
        def __exit__(self, *a):
            return False
    with CM() as C:
        C()()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    match (Mut,):
        case (*xs,):
            xs[0]()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        _never_authorized(_unit(routes))


def test_persistent_version_bumped_for_lexical_closure() -> None:
    assert PERSISTENT_FASTAPI_STATE_IMPLEMENTATION_VERSION == "0.91.0"
