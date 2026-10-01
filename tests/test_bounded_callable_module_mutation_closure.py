"""Bounded callable/module mutation closure (#163).

Adversarial coverage: conditional/compound module-export mutation, module
namespace surfaces (__dict__/vars/update), callable-object mutation, sys.modules,
pre/post-import ordering, and restoring unconditional rebinding.
Unknown > false PASS. Shared by bypass writer closure and argument provenance.
"""

from __future__ import annotations

from ovk.compilers.authorization.bypass_authority import (
    ClosedWorldScopeProof,
    analyze_bypass_authority_unit,
)
from ovk.compilers.authorization.interprocedural_argument_provenance import (
    analyze_interprocedural_argument_provenance,
)
from ovk.compilers.authorization.python_callee_resolution import (
    build_callee_resolver_from_sources,
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


def test_conditional_module_attr_assignment_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
if ENABLE_EXTERNAL:
    helpers.write_state = evil_writer
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_conditional_setattr_module_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
if FLAG:
    setattr(helpers, "write_state", evil)
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_try_block_module_attr_assignment_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
try:
    helpers.write_state = external_writer
except ImportError:
    pass
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_module_dunder_dict_name_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
helpers.__dict__["write_state"] = evil_writer
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_vars_module_name_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
vars(helpers)["write_state"] = evil_writer
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_module_dunder_dict_update_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
helpers.__dict__.update({{"write_state": evil_writer}})
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_imported_fn_dunder_code_cannot_authorize() -> None:
    findings = _unit(
        f"""
from helpers import write_state
write_state.__code__ = evil_writer.__code__
{_handler_attr("write_state")}
"""
    )
    assert findings[0].status == "unknown"


def test_imported_fn_dunder_globals_cannot_authorize() -> None:
    findings = _unit(
        f"""
from helpers import write_state
write_state.__globals__["SECRET"] = client_value
{_handler_attr("write_state")}
"""
    )
    assert findings[0].status == "unknown"


def test_module_attr_mutation_before_import_cannot_authorize() -> None:
    """Final import_module binding still sees earlier mutation of the alias."""

    findings = _unit(
        f"""
helpers.write_state = evil_writer
import helpers
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_module_attr_mutation_after_import_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
helpers.write_state = evil_writer
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_callable_mutation_before_import_cannot_authorize() -> None:
    findings = _unit(
        f"""
write_state.__code__ = evil_writer.__code__
from helpers import write_state
{_handler_attr("write_state")}
"""
    )
    assert findings[0].status == "unknown"


def test_callable_mutation_after_import_cannot_authorize() -> None:
    findings = _unit(
        f"""
from helpers import write_state
write_state.__defaults__ = (True,)
{_handler_attr("write_state")}
"""
    )
    assert findings[0].status == "unknown"


def test_later_unconditional_local_def_restores_source_grounded_export() -> None:
    findings = _unit(
        f"""
import helpers
helpers.write_state = evil_writer
def write_state(state, value):
    state.bypass_filter = value
{_handler_attr("write_state")}
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_later_unconditional_def_restores_after_callable_mutation() -> None:
    findings = _unit(
        f"""
from helpers import write_state
write_state.__code__ = evil_writer.__code__
def write_state(state, value):
    state.bypass_filter = value
{_handler_attr("write_state")}
"""
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_sys_modules_mutation_cannot_authorize() -> None:
    findings = _unit(
        f"""
import sys
import helpers
sys.modules["helpers"].write_state = evil_writer
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_for_body_module_attr_mutation_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
for _ in items:
    helpers.write_state = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_with_body_setattr_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
with ctx:
    setattr(helpers, "write_state", evil)
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_match_case_module_dict_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
match value:
    case 1:
        helpers.__dict__["write_state"] = evil
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_qualified_callable_attr_mutation_cannot_authorize() -> None:
    findings = _unit(
        f"""
import helpers
helpers.write_state.__code__ = evil_writer.__code__
{_handler_attr()}
"""
    )
    assert findings[0].status == "unknown"


def test_mutation_closure_shared_with_argument_provenance() -> None:
    files = {
        "app/helpers.py": _helpers_source(body="value"),
        "app/routes.py": f"""
from helpers import write_state
write_state.__code__ = evil.__code__
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


def test_resolver_refuses_callable_behavior_without_module_rebinding() -> None:
    resolver = build_callee_resolver_from_sources(
        {
            "app/helpers.py": _helpers_source(),
            "app/routes.py": """
from helpers import write_state
write_state.__kwdefaults__ = {"value": True}
""".strip(),
        },
        import_roots=("app",),
    )
    binding = resolver.bindings_by_path["app/routes.py"]["write_state"]
    assert binding.kind == "import_name"
    assert binding.behavior_established is False
    import ast

    call = ast.parse("write_state(s, v)").body[0].value  # type: ignore[attr-defined]
    result = resolver.resolve_call(call.func, caller_path="app/routes.py")
    assert result.resolved is False
    assert result.reason == "callable_behavior_unknown"
