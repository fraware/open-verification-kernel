"""Request-time callable identity invalidation (#167).

#166 mutation analysis covers module-initialization. Trusted-bypass writer
reasoning runs on request-time handler execution. Handler-body mutations of
module exports / callable behavior before authorizing calls must invalidate
callable identity from the mutation point onward (Unknown > false PASS).

Phase-sensitive: mutation after a protected call does not invalidate that
earlier call; mutation between two calls invalidates only the later one.

Adversarial harden pass closes additional request-time false-PASS surfaces
(async helpers, class/bound/static methods, factory receivers, getattr /
methodcaller, benign-builtin argument evaluation including map/filter and
list(genexp), delattr / attrsetter) via the shared #166 identity session.

Intentional residuals (Unknown > false PASS when observed; not authorizing):
- Methods reached only through fully dynamic names (non-static getattr /
  methodcaller / attrsetter attribute expressions).
- Mutation inside C-extension / foreign callables with no AST body in the
  accounted closed-world unit.
- Metaclass / ``type(...)`` synthesized callables not present as ClassDef
  methods in the unit.
Held-out FormalPR partitions are not frozen by this change.
"""

from __future__ import annotations

from ovk.compilers.authorization.bypass_authority import (
    ClosedWorldScopeProof,
    analyze_bypass_authority_unit,
)
from ovk.compilers.authorization.interprocedural_argument_provenance import (
    analyze_interprocedural_argument_provenance,
)
from ovk.compilers.authorization.incremental_fastapi_compiler import (
    compile_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
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


def test_handler_module_export_assign_then_call_cannot_authorize() -> None:
    """1. helpers.write_state = evil then helpers.write_state(...)."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    request.state.bypass_filter = True
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_handler_dunder_code_then_call_cannot_authorize() -> None:
    """2. write_state.__code__ = evil.__code__ then call."""

    findings = _unit(
        """
from helpers import write_state
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    write_state.__code__ = evil.__code__
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_handler_mutate_via_module_alias_cannot_authorize() -> None:
    """3. Mutate via m = helpers."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    m = helpers
    m.write_state = evil
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_handler_mutate_via_callable_alias_cannot_authorize() -> None:
    """4. Mutate via f = write_state."""

    findings = _unit(
        """
from helpers import write_state
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    f = write_state
    f.__code__ = evil.__code__
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_handler_zero_arg_local_helper_mutation_cannot_authorize() -> None:
    """5. Zero-arg local helper mutates module export then call."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_handler_helper_receives_module_arg_mutation_cannot_authorize() -> None:
    """6. Helper receives module/callable arg and mutates."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison(m):
        m.write_state = evil
    poison(helpers)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_handler_branch_only_mutation_before_call_cannot_authorize() -> None:
    """7. Mutation only on one branch before call → UNKNOWN."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    if bypass_filter:
        helpers.write_state = evil
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_handler_mutation_after_call_does_not_invalidate() -> None:
    """8. Mutation after protected call → does not invalidate earlier call."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state(request.state, True)
    helpers.write_state = evil
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_handler_mutation_then_source_grounded_rebind_may_reestablish() -> None:
    """9. Mutation then explicit source-grounded rebinding before call."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    def write_state(state, value):
        state.bypass_filter = True
    helpers.write_state = write_state
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    # May re-establish to the nested trusted writer → authorized, or stay
    # UNKNOWN. Never false-PASS through the poisoned evil binding.
    assert findings[0].status in {"authorized", "unknown"}
    if findings[0].status == "authorized":
        assert findings[0].reason == "source_proved_server_authority_write"


def test_handler_two_calls_mutation_between_second_loses_identity() -> None:
    """10. Two calls with mutation between: second loses identity."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state(request.state, True)
    helpers.write_state = evil
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_handler_dependency_helper_mutation_before_sink_cannot_authorize() -> None:
    """11. Mutation in dependency/helper executed before handler sink."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def poison():
    helpers.write_state = evil
def handler(request, bypass_filter=False):
    poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_request_time_false_pass_composition_never_authorizes() -> None:
    """12. Full composition: the false-PASS program yields UNKNOWN, never PASS."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    request.state.bypass_filter = True
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status == "unknown"


def test_handler_name_bound_lambda_mutation_cannot_authorize() -> None:
    """Audit: poison = lambda: setattr(...); poison() then call."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    poison = lambda: setattr(helpers, "write_state", evil)
    poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_request_time_identity_shared_with_argument_provenance() -> None:
    files = {
        "app/helpers.py": _helpers_source(body="value"),
        "app/routes.py": """
from helpers import write_state
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    write_state.__code__ = evil.__code__
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
    }
    findings = analyze_bypass_authority_unit(
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
    assert findings[0].status == "unknown"
    prov = analyze_interprocedural_argument_provenance(
        files,
        callee_name="write_state",
        parameter="value",
        scope_proof=_scope(
            "app/helpers.py",
            "app/routes.py",
            import_roots=("app",),
        ),
    )
    # Module-init snapshot still sees the FunctionDef; request-time mutation is
    # shared with provenance (#167) so the callsite must not authorize.
    assert prov.provenance == "unknown"


def test_async_helper_mutation_before_call_cannot_authorize() -> None:
    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
async def poison():
    helpers.write_state = evil
async def handler(request, bypass_filter=False):
    await poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_nested_async_helper_mutation_cannot_authorize() -> None:
    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
async def handler(request, bypass_filter=False):
    async def poison():
        helpers.write_state = evil
    await poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_method_mutator_before_call_cannot_authorize() -> None:
    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
class Mut:
    def poison(self):
        helpers.write_state = evil
def handler(request, bypass_filter=False):
    Mut().poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_classmethod_staticmethod_bound_method_cannot_authorize() -> None:
    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
class Mut:
    @classmethod
    def poison(cls):
        helpers.write_state = evil
def handler(request, bypass_filter=False):
    Mut.poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
class Mut:
    @staticmethod
    def poison():
        helpers.write_state = evil
def handler(request, bypass_filter=False):
    Mut.poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
class Mut:
    def poison(self):
        helpers.write_state = evil
def handler(request, bypass_filter=False):
    m = Mut()
    p = m.poison
    p()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        assert _unit(routes)[0].status == "unknown"


def test_factory_getattr_methodcaller_mutation_cannot_authorize() -> None:
    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
class Mut:
    def poison(self):
        helpers.write_state = evil
def make():
    return Mut()
def handler(request, bypass_filter=False):
    make().poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
class Mut:
    def poison(self):
        helpers.write_state = evil
def handler(request, bypass_filter=False):
    getattr(Mut(), "poison")()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
class Mut:
    def poison(self):
        helpers.write_state = evil
def handler(request, bypass_filter=False):
    operator.methodcaller("poison")(Mut())
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        assert _unit(routes)[0].status == "unknown"


def test_setattr_delattr_attrsetter_mutation_cannot_authorize() -> None:
    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    setattr(helpers, "write_state", evil)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    delattr(helpers, "write_state")
    helpers.write_state = evil
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    operator.attrsetter("write_state")(helpers, evil)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        assert _unit(routes)[0].status == "unknown"


def test_finally_except_comprehension_generator_mutation_ordering() -> None:
    # Mutation in finally before a later call → UNKNOWN.
    assert (
        _unit(
            """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    try:
        x = 1
    finally:
        helpers.write_state = evil
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        )[0].status
        == "unknown"
    )
    # Mutation after a protected call (finally) must not rewind the earlier call.
    after = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    try:
        helpers.write_state(request.state, True)
    finally:
        helpers.write_state = evil
    return request.state.bypass_filter
"""
    )[0]
    # Control-dependent try/finally may stay UNKNOWN; never false-PASS the
    # post-mutation identity onto the earlier call.
    assert after.status in {"authorized", "unknown"}
    if after.status == "authorized":
        assert after.reason == "source_proved_server_authority_write"
    # Comprehension / generator executed before call.
    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    _ = [setattr(helpers, "write_state", evil) for _ in [0]]
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    list(setattr(helpers, "write_state", evil) for _ in [0])
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def poison(_):
    helpers.write_state = evil
def handler(request, bypass_filter=False):
    list(map(poison, [0]))
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        assert _unit(routes)[0].status == "unknown"


def test_dual_alias_modules_and_depends_factory_cannot_authorize() -> None:
    assert (
        _unit(
            """
import helpers as h1
import helpers as h2
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    h1.write_state = evil
    h2.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        )[0].status
        == "unknown"
    )
    assert (
        _unit(
            """
import helpers
def evil(state, value):
    state.bypass_filter = value
def get_writer():
    helpers.write_state = evil
    return helpers.write_state
def handler(request, bypass_filter=False):
    w = get_writer()
    w(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        )[0].status
        == "unknown"
    )


def test_midcall_helper_mutates_then_writes_cannot_authorize() -> None:
    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def poison_and_write(state, value):
    helpers.write_state = evil
    helpers.write_state(state, value)
def handler(request, bypass_filter=False):
    poison_and_write(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_writer_provenance_request_time_overlays_agree_unknown() -> None:
    """Dual analysis: writer and provenance share request-time overlays."""

    routes = """
import helpers
def evil(state, value):
    state.bypass_filter = value
class Mut:
    def poison(self):
        helpers.write_state = evil
def handler(request, bypass_filter=False):
    Mut().poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip()
    files = {
        "app/helpers.py": _helpers_source(),
        "app/routes.py": routes,
    }
    findings = analyze_bypass_authority_unit(
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
    assert findings[0].status == "unknown"
    prov = analyze_interprocedural_argument_provenance(
        files,
        callee_name="write_state",
        parameter="value",
        scope_proof=_scope(
            "app/helpers.py",
            "app/routes.py",
            import_roots=("app",),
        ),
    )
    assert prov.provenance == "unknown"


def test_handler_body_mutation_full_equals_incremental() -> None:
    """Only handler body gains mutation → IR changes; full == incremental."""

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
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    helpers.write_state = evil
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
            repo="example/request-time-identity",
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