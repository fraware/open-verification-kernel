"""Bounded module/callable object-alias provenance (#165).

Adversarial coverage: statement-order ModuleObject / CallableObject /
ModuleNamespace aliases, interprocedural actual→formal binding, conditional
alias joins, reassignment severance, container escape → UNKNOWN, and lattice
refinement of bottom vs unknown receivers (export-spelling poison without
breaking severance). Unknown > false PASS. Shared by bypass writer closure
and argument provenance.
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


def _handler_attr(callee: str = "helpers.write_state") -> str:
    return f"""
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    {callee}(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip()


def _helpers_source(*, body: str = "True") -> str:
    return f"""
def write_state(state, value):
    state.bypass_filter = {body}
""".strip()


def _unit(
    routes: str,
    *,
    helpers: str | None = None,
    callee: str = "helpers.write_state",
) -> object:
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


def test_module_alias_attr_assignment_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
m = helpers
m.write_state = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_module_dict_alias_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
d = helpers.__dict__
d["write_state"] = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_vars_alias_update_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
d = vars(helpers)
d.update(write_state=evil)
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_callable_alias_dunder_code_cannot_authorize() -> None:
    findings = _unit(
        f"""
from helpers import write_state
f = write_state
f.__code__ = evil.__code__
{_handler_attr("write_state")}
"""
    )
    assert findings[0].status == "unknown"


def test_qualified_callable_alias_globals_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
f = helpers.write_state
f.__globals__["x"] = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_local_helper_module_actual_mutation_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
def poison(mod):
    mod.write_state = evil
poison(helpers)
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_local_helper_callable_actual_mutation_cannot_authorize() -> None:
    findings = _unit(
        f"""
from helpers import write_state
def mutate(fn):
    fn.__code__ = evil.__code__
mutate(write_state)
{_handler_attr("write_state")}
"""
    )
    assert findings[0].status == "unknown"


def test_chained_module_aliases_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
m2 = m1 = helpers
m2.write_state = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_alias_reassignment_before_mutation_severs_identity() -> None:
    findings = _unit(
        f"""
import helpers
m = helpers
m = something_else
m.write_state = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_statement_order_mutation_before_reassignment_poisons() -> None:
    findings = _unit(
        f"""
import helpers
m = helpers
m.write_state = evil
m = something_else
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_conditional_alias_mutation_poisons_possible_target() -> None:
    findings = _unit(
        f"""
import helpers
m = other
if FLAG:
    m = helpers
m.write_state = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_tuple_packing_container_escape_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
t = (helpers,)
t[0].write_state = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_list_packing_container_escape_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
items = [helpers]
items[0].write_state = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_alias_identity_shared_with_argument_provenance() -> None:
    files = {
        "app/helpers.py": _helpers_source(body="value"),
        "app/routes.py": f"""
from helpers import write_state
f = write_state
f.__code__ = evil.__code__
{_handler_attr("write_state")}
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
    assert prov.provenance == "unknown"


def test_clean_module_alias_without_mutation_still_authorizes() -> None:
    findings = _unit(
        f"""
import helpers
m = helpers
{_handler_attr()}
"""
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_getattr_alias_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
f = getattr(helpers, "write_state")
f.__code__ = evil.__code__
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_ternary_and_boolop_alias_cannot_authorize() -> None:
    findings = _unit(
        f"""
from helpers import write_state
f = write_state if True else other
f.__code__ = evil.__code__
{_handler_attr("write_state")}
"""
    )
    assert findings[0].status == "unknown"


def test_walrus_attr_mutation_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
(m := helpers).write_state = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_nested_helper_closure_mutation_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
def outer(mod):
    def inner():
        mod.write_state = evil
    inner()
outer(helpers)
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_comprehension_container_escape_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
xs = [helpers for _ in [0]]
xs[0].write_state = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_match_alias_escape_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
match helpers:
    case m:
        m.write_state = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_getattr_module_dict_cannot_authorize() -> None:
    """getattr(module, \"__dict__\") must be ModuleNamespace, not CallableObject."""

    findings = _unit(
        f"""
import helpers
d = getattr(helpers, "__dict__")
d["write_state"] = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_kwonly_actual_formal_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
def poison(*, mod):
    mod.write_state = evil
poison(mod=helpers)
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_default_value_identity_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
def f(m=helpers):
    m.write_state = evil
f()
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_returned_closure_mutation_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
def make():
    m = helpers
    def inner():
        m.write_state = evil
    return inner
make()()
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_for_iter_container_escape_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
for m in [helpers]:
    m.write_state = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_unknown_receiver_export_spelling_cannot_authorize() -> None:
    """Unmodeled values may alias a module; export-shaped writes must UNKNOWN.

    Distinct from severance: ``m = other`` is bottom (no tracked identity) and
    may still authorize after reassignment.
    """

    findings = _unit(
        f"""
import helpers
m = unknown()
m.write_state = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_unknown_receiver_unrelated_attr_still_authorizes() -> None:
    findings = _unit(
        f"""
import helpers
m = unknown()
m.unrelated = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_class_body_module_mutation_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
class C:
    helpers.write_state = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_decorator_helper_mutation_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
def deco(f):
    helpers.write_state = evil
    return f
@deco
def g():
    pass
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_diamond_alias_and_from_import_as_still_poison() -> None:
    findings = _unit(
        f"""
from helpers import write_state as w
f = w
g = f
g.__code__ = evil.__code__
{_handler_attr("write_state")}
"""
    )
    assert findings[0].status == "unknown"
