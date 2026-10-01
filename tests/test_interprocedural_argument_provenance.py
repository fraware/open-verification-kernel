"""Bounded interprocedural argument provenance (#141)."""

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
    files = {
        "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
        "app/caller.py": """
from helper import generate

def route(request):
    generate(request, True)
""".strip(),
    }
    # Import alias maps generate -> helper.generate name "generate"
    files["app/caller.py"] = """
def route(request):
    generate(request, True)
""".strip()
    files["app/helper.py"] = files["app/helper.py"]
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


def test_attribute_callsite_matching_callee_poisons_lattice() -> None:
    """Adversarial: module.callee Attribute forms must not be silently omitted."""

    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
import helper

def route(request, bypass_filter: bool = False):
    generate(request, True)
    helper.generate(request, bypass_filter)
""".strip(),
        },
        callee_name="generate",
        parameter="bypass_filter",
        scope_proof=_scope("app/helper.py", "app/caller.py"),
    )
    assert result.provenance == "unknown"
    assert any(
        item.unresolved_reason == "deferred_callee_form" for item in result.callsites
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


def test_module_level_import_rebinding_poisons_callsite() -> None:
    result = analyze_interprocedural_argument_provenance(
        {
            "app/helper.py": """
def generate(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter
""".strip(),
            "app/caller.py": """
from app.helper import generate
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
    assert result.reason == "unresolved_callsite_or_deferred_form"
    assert any(
        item.unresolved_reason == "module_level_callee_rebinding"
        for item in result.callsites
    )


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

