"""Bounded Python module-binding semantics (#161).

Adversarial coverage: conditional/compound bindings, decorators, import-root
contract, dynamic namespace mutation, cross-module exported-name mutation.
Unknown > false PASS.
"""

from __future__ import annotations

from ovk.compilers.authorization.bypass_authority import (
    ClosedWorldScopeProof,
    analyze_bypass_authority,
    analyze_bypass_authority_unit,
)
from ovk.compilers.authorization.python_callee_resolution import (
    build_callee_resolver_from_sources,
    module_final_bindings,
)
from ovk.compilers.authorization.python_import_space import (
    module_candidates_in_manifest,
)
from ovk.core.protected_effect_profile import ProtectedEffectProfileConfig
from ovk.compilers.authorization.fastapi_semantic_fragment import (
    profile_semantic_digest,
)
import ast


def _scope(*paths: str, import_roots: tuple[str, ...] = ()) -> ClosedWorldScopeProof:
    return ClosedWorldScopeProof(
        accounted_paths=tuple(paths),
        source_roots=(".",),
        python_import_roots=import_roots,
    )


def _handler_template(callee: str = "write_state") -> str:
    return f"""
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    {callee}(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip()


def test_conditional_external_import_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        f"""
def write_state(state, value):
    state.bypass_filter = True
if USE_EXTERNAL:
    from external import write_state
{_handler_template()}
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_try_except_optional_import_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        f"""
def write_state(state, value):
    state.bypass_filter = True
try:
    from optional import write_state
except ImportError:
    pass
{_handler_template()}
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_conditional_assignment_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        f"""
def write_state(state, value):
    state.bypass_filter = True
if FLAG:
    write_state = evil
{_handler_template()}
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_later_unconditional_def_restores_identity_after_uncertain_overwrite() -> None:
    findings = analyze_bypass_authority(
        f"""
def write_state(state, value):
    state.bypass_filter = True
if FLAG:
    write_state = evil
def write_state(state, value):
    state.bypass_filter = value
{_handler_template()}
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_for_body_rebinding_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        f"""
def write_state(state, value):
    state.bypass_filter = True
for item in items:
    write_state = item
{_handler_template()}
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_with_body_rebinding_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        f"""
def write_state(state, value):
    state.bypass_filter = True
with ctx:
    write_state = evil
{_handler_template()}
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_match_case_rebinding_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        f"""
def write_state(state, value):
    state.bypass_filter = True
match value:
    case 1:
        write_state = evil
{_handler_template()}
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_while_body_rebinding_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        f"""
def write_state(state, value):
    state.bypass_filter = True
while FLAG:
    write_state = evil
{_handler_template()}
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_decorator_transforms_refuse_authorizing_identity() -> None:
    findings = analyze_bypass_authority(
        f"""
def replace(fn):
    def wrapped(state, value):
        state.bypass_filter = value
    return wrapped

@replace
def write_state(state, value):
    state.bypass_filter = True
{_handler_template()}
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_import_root_nested_helpers_without_roots_is_unknown() -> None:
    """``from helpers import f`` with only ``app/helpers.py`` → UNKNOWN."""

    findings = analyze_bypass_authority_unit(
        {
            "app/helpers.py": """
def write_state(state, value):
    state.bypass_filter = value
""".strip(),
            "app/routes.py": f"""
from helpers import write_state
{_handler_template()}
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/helpers.py", "app/routes.py"),
    )
    assert findings[0].status == "unknown"


def test_import_root_nested_helpers_with_trusted_root_resolves() -> None:
    findings = analyze_bypass_authority_unit(
        {
            "app/helpers.py": """
def write_state(state, value):
    state.bypass_filter = value
""".strip(),
            "app/routes.py": f"""
from helpers import write_state
{_handler_template()}
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope(
            "app/helpers.py",
            "app/routes.py",
            import_roots=("app",),
        ),
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_import_root_exact_repo_root_helpers_resolves() -> None:
    findings = analyze_bypass_authority_unit(
        {
            "helpers.py": """
def write_state(state, value):
    state.bypass_filter = value
""".strip(),
            "routes.py": f"""
from helpers import write_state
{_handler_template()}
""".strip(),
        },
        entry_path="routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("helpers.py", "routes.py"),
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_ambiguous_import_roots_remain_unknown() -> None:
    assert module_candidates_in_manifest(
        "helpers",
        {"backend/helpers.py", "src/helpers.py"},
        import_roots=("backend", "src"),
    ) == ("backend/helpers.py", "src/helpers.py")
    findings = analyze_bypass_authority_unit(
        {
            "backend/helpers.py": """
def write_state(state, value):
    state.bypass_filter = True
""".strip(),
            "src/helpers.py": """
def write_state(state, value):
    state.bypass_filter = value
""".strip(),
            "app/routes.py": f"""
from helpers import write_state
{_handler_template()}
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope(
            "backend/helpers.py",
            "src/helpers.py",
            "app/routes.py",
            import_roots=("backend", "src"),
        ),
    )
    assert findings[0].status == "unknown"


def test_relative_import_still_source_grounded() -> None:
    findings = analyze_bypass_authority_unit(
        {
            "pkg/helpers.py": """
def write_state(state, value):
    state.bypass_filter = value
""".strip(),
            "pkg/sub/routes.py": f"""
from ..helpers import write_state
{_handler_template()}
""".strip(),
        },
        entry_path="pkg/sub/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("pkg/helpers.py", "pkg/sub/routes.py"),
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_globals_subscript_mutation_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        f"""
def write_state(state, value):
    state.bypass_filter = True
globals()["write_state"] = evil
{_handler_template()}
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_globals_update_mutation_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        f"""
def write_state(state, value):
    state.bypass_filter = True
globals().update({{"write_state": evil}})
{_handler_template()}
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_module_dunder_dict_mutation_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        f"""
def write_state(state, value):
    state.bypass_filter = True
__dict__["write_state"] = evil
{_handler_template()}
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_exec_rebinding_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        f"""
def write_state(state, value):
    state.bypass_filter = True
exec("write_state = evil")
{_handler_template()}
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_cross_module_exported_name_mutation_cannot_authorize() -> None:
    findings = analyze_bypass_authority_unit(
        {
            "app/helpers.py": """
def write_state(state, value):
    state.bypass_filter = True
""".strip(),
            "app/routes.py": f"""
import helpers
helpers.write_state = evil
{_handler_template("helpers.write_state")}
""".strip(),
        },
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


def test_setattr_cross_module_mutation_cannot_authorize() -> None:
    findings = analyze_bypass_authority_unit(
        {
            "app/helpers.py": """
def write_state(state, value):
    state.bypass_filter = True
""".strip(),
            "app/routes.py": f"""
import helpers
setattr(helpers, "write_state", evil)
{_handler_template("helpers.write_state")}
""".strip(),
        },
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


def test_callee_and_closed_world_share_import_primitive() -> None:
    """Suffix-only matching must not authorize when roots disagree."""

    files = {
        "app/helpers.py": "def write_state(state, value):\n    state.bypass_filter = value\n",
        "app/routes.py": "from helpers import write_state\n",
    }
    # No roots: neither resolver nor closed-world may treat as unique local.
    resolver = build_callee_resolver_from_sources(files)
    call = ast.parse("write_state(x, y)").body[0].value  # type: ignore[attr-defined]
    result = resolver.resolve_call(call.func, caller_path="app/routes.py")
    assert result.resolved is False
    findings = analyze_bypass_authority_unit(
        {
            **files,
            "app/routes.py": f"""
from helpers import write_state
{_handler_template()}
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/helpers.py", "app/routes.py"),
    )
    assert findings[0].status == "unknown"
    assert findings[0].closed_world is not None
    assert findings[0].closed_world.complete is False


def test_profile_python_import_roots_in_semantic_digest() -> None:
    base = {
        "schema_version": "ovk.protected_effect_profile.v1",
        "profile_type": "fastapi_dependency_effects_v1",
        "source_paths": ["app/**/*.py"],
        "sink_effects": {"sink": "model.invoke"},
        "dependency_guard_resources": {"dep": "resource"},
        "dependency_guard_effects": {"dep": ["model.invoke"]},
    }
    without = ProtectedEffectProfileConfig.model_validate(base)
    with_roots = ProtectedEffectProfileConfig.model_validate(
        {**base, "python_import_roots": ["app"]}
    )
    assert with_roots.python_import_roots == ["app"]
    assert profile_semantic_digest(without) != profile_semantic_digest(with_roots)


def test_module_final_bindings_marks_decorated_def_rebound() -> None:
    tree = ast.parse(
        """
@replace
def write_state(state, value):
    pass
""".strip()
    )
    bindings = module_final_bindings(tree, path="<module>")
    assert bindings["write_state"].kind == "rebound"
