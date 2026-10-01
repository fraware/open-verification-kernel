"""Bounded interprocedural argument provenance (#141 / #160)."""

from __future__ import annotations

from ovk.compilers.authorization.bypass_authority import ClosedWorldScopeProof
from ovk.compilers.authorization.interprocedural_argument_provenance import (
    analyze_interprocedural_argument_provenance,
)


def _scope(*paths: str) -> ClosedWorldScopeProof:
    return ClosedWorldScopeProof(
        accounted_paths=tuple(paths),
        source_roots=(".",),
    )


def test_all_literal_callsites_are_server_internal() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
from helper import generate

def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "server_internal"
    assert result.callsites
    assert all(item.origin_kind == "literal_constant" for item in result.callsites)


def test_http_parameter_callsite_is_external() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
from helper import generate

def route(request, bypass_filter: bool = False):
    generate(request, bypass_filter)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "externally_bound_http"
    assert result.callsites[0].origin_kind == "externally_bound_http_value"


def test_starargs_callsite_is_unknown() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
from helper import generate

def route(request, args):
    generate(request, *args)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "unresolved_callsite_or_deferred_form"


def test_scope_mismatch_is_unknown() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": "def generate(request, bypass_filter=False):\n    pass\n",
            "app/caller.py": "def route(request):\n    generate(request, True)\n",
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "scope_proof_file_set_mismatch"


def test_no_callsites_is_unknown_not_internal() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "no_accounted_callsites"


def test_imported_name_call_resolves_uniquely() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
from helper import generate as gen

def route(request):
    gen(request, False)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "server_internal"
    assert len(result.callsites) == 1


def test_recursive_call_is_unknown() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    if bypass_filter:
        return generate(request, True)
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
from helper import generate

def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "unknown"
    assert any(
        item.unresolved_reason == "recursive_call_deferred"
        for item in result.callsites
    )


def test_module_attribute_callsite_resolves_uniquely() -> None:
    """``import helper; helper.generate(...)`` follows unique module identity."""

    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
import helper

def route(request, bypass_filter: bool = False):
    helper.generate(request, bypass_filter)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "externally_bound_http"
    assert len(result.callsites) == 1


def test_unresolved_attribute_callsite_matching_callee_poisons_lattice() -> None:
    """Unresolved ``obj.generate`` whose attr matches the callee must poison."""

    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
from helper import generate

def route(request, bypass_filter: bool = False, obj=None):
    generate(request, True)
    obj.generate(request, bypass_filter)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "unknown"
    assert any(
        item.unresolved_reason
        in {"deferred_callee_form", "shadowed_local_binding", "deferred_module_attribute"}
        for item in result.callsites
    )


def test_parameter_shadowing_does_not_count_as_global_callsite() -> None:
    """Adversarial: def route(generate): generate(...) is not global generate."""

    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
def route(generate):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "no_accounted_callsites"
    assert result.callsites == ()


def test_local_assignment_shadowing_does_not_count_as_global_callsite() -> None:
    """Local rebinding of the callee name must not authorize caller provenance."""

    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
def route(request):
    generate = other_fn
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "no_accounted_callsites"


def test_nested_def_shadowing_does_not_pollute_callsite_lattice() -> None:
    """Nested def generate(...) must not count as a global generate callsite."""

    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
def route(request):
    def generate(request, bypass_filter: bool = False):
        request.state.bypass_filter = True
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "no_accounted_callsites"
    assert result.callsites == ()


def test_module_level_rebinding_does_not_authorize_original_callee() -> None:
    """``generate = other_callable`` after ``def generate`` must not authorize."""

    result = analyze_interprocedural_argument_provenance(
        {
            "app/mod.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
generate = other_callable
def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/mod.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "callee_not_uniquely_resolved"


def test_module_level_tuple_unpack_rebinding_does_not_authorize() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/mod.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
(generate,) = (other_callable,)
def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/mod.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "callee_not_uniquely_resolved"


def test_module_level_import_rebinding_omits_callsite() -> None:
    """Import then assignment overwrite is not the imported callee identity."""

    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
from helper import generate
generate = other_callable
def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "no_accounted_callsites"


def test_later_def_restores_function_binding_after_temp_rebind() -> None:
    """A later ``def generate`` restores the authorizing function identity."""

    result = analyze_interprocedural_argument_provenance(
        {
            "app/mod.py": """
generate = other_callable
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/mod.py"),
    )
    assert result.provenance == "server_internal"


def test_external_import_same_leaf_does_not_match_unrelated_local() -> None:
    """``from thirdparty import generate`` must not authorize local generate."""

    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
from thirdparty import generate

def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "no_accounted_callsites"


def test_unimported_same_named_function_elsewhere_never_resolves() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "no_accounted_callsites"


def test_star_import_after_def_cannot_authorize_original_callee() -> None:
    """``from evil import *`` may overwrite ``generate`` — refuse server_internal."""

    result = analyze_interprocedural_argument_provenance(
        {
            "app/mod.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
from evil import *
def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/mod.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "callee_not_uniquely_resolved"


def test_for_loop_rebinding_cannot_authorize_original_callee() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/mod.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
for generate in [evil]:
    pass
def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/mod.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "callee_not_uniquely_resolved"


def test_except_as_rebinding_cannot_authorize_original_callee() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/mod.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
try:
    raise Exception()
except Exception as generate:
    pass
def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/mod.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "callee_not_uniquely_resolved"


def test_match_pattern_rebinding_cannot_authorize_original_callee() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/mod.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
match 1:
    case generate:
        pass
def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/mod.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "callee_not_uniquely_resolved"


def test_del_rebinding_cannot_authorize_original_callee() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/mod.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
del generate
def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/mod.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "callee_not_uniquely_resolved"


def test_relative_import_callsite_resolves_uniquely() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "pkg/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "pkg/sub/caller.py": """
from ..helper import generate

def route(request):
    generate(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("pkg/helper.py", "pkg/sub/caller.py"),
    )
    assert result.provenance == "server_internal"
    assert len(result.callsites) == 1


def test_package_init_reexport_callsite_resolves_uniquely() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper/impl.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/helper/__init__.py": "from app.helper.impl import generate\n",
            "app/caller.py": """
from app.helper import generate

def route(request):
    generate(request, False)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope(
            "app/helper/impl.py",
            "app/helper/__init__.py",
            "app/caller.py",
        ),
    )
    assert result.provenance == "server_internal"
    assert len(result.callsites) == 1


def test_same_leaf_different_packages_follows_imported_package() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "pkg_a/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "pkg_b/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
from pkg_b.helper import generate

def route(request, bypass_filter: bool = False):
    generate(request, bypass_filter)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope(
            "pkg_a/helper.py",
            "pkg_b/helper.py",
            "app/caller.py",
        ),
    )
    # Two leaf defs → target selection refuses uniqueness.
    assert result.provenance == "unknown"
    assert result.reason == "callee_not_uniquely_resolved"


def test_getattr_callsite_matching_callee_poisons_lattice() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
import helper

def route(request):
    generate = helper.generate
    getattr(helper, "generate")(request, True)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "unknown"
    assert result.reason == "unresolved_callsite_or_deferred_form"


def test_writer_and_provenance_agree_on_import_alias() -> None:
    """Shared resolver: ``as ws`` must agree across writer closure and provenance."""

    from ovk.compilers.authorization.bypass_authority import (
        analyze_bypass_authority_unit,
    )

    files = {
        "app/helpers.py": """
def write_state(state, value):
    state.bypass_filter = value
""".strip(),
        "app/routes.py": """
from helpers import write_state as ws

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    ws(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
    }
    writer = analyze_bypass_authority_unit(
        files,
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/helpers.py", "app/routes.py"),
    )
    prov = analyze_interprocedural_argument_provenance(
        {
            "app/helpers.py": """
def write_state(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/routes.py": """
from helpers import write_state as ws

def route(request, bypass_filter: bool = False):
    ws(request, bypass_filter)
""".strip(),
        },
        callee_name="write_state",
        parameter="bypass_filter",
        scope_proof=_scope("app/helpers.py", "app/routes.py"),
    )
    assert writer[0].status == "violated"
    assert prov.provenance == "externally_bound_http"
