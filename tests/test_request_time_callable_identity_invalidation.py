"""Request-time callable identity invalidation (#167).

#166 mutation analysis covers module-initialization. Trusted-bypass writer
reasoning runs on request-time handler execution. Handler-body mutations of
module exports / callable behavior before authorizing calls must invalidate
callable identity from the mutation point onward (Unknown > false PASS).

Phase-sensitive: mutation after a protected call does not invalidate that
earlier call; mutation between two calls invalidates only the later one.
"""

from __future__ import annotations

from ovk.compilers.authorization.bypass_authority import (
    ClosedWorldScopeProof,
    analyze_bypass_authority_unit,
)
from ovk.compilers.authorization.interprocedural_argument_provenance import (
    analyze_interprocedural_argument_provenance,
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
    # a bypass concern. Provenance must not false-PASS when behavior is
    # mutated at module level; here mutation is request-time only so provenance
    # may remain server_internal or unknown — never invent a false PASS path
    # for the bypass finding above.
    # Module-init snapshot still sees the FunctionDef; request-time mutation is
    # shared with provenance (#167) so the callsite must not authorize.
    assert prov.provenance == "unknown"
