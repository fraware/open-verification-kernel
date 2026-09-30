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
