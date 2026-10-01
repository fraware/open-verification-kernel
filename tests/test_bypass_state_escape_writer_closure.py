"""Request/state escape analysis + interprocedural writer closure (#156)."""

from __future__ import annotations

from ovk.compilers.authorization.bypass_authority import (
    ClosedWorldScopeProof,
    analyze_bypass_authority,
    analyze_bypass_authority_unit,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)


def _scope(*paths: str) -> ClosedWorldScopeProof:
    return ClosedWorldScopeProof(
        accounted_paths=tuple(paths),
        source_roots=(".",),
    )


def test_helper_state_formal_client_write_cannot_authorize() -> None:
    """``write_state(request.state, client)`` must not leave only the literal write."""

    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = value

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"
    assert findings[0].write_count >= 2


def test_helper_state_formal_client_write_is_violated() -> None:
    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = value

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_dict_mutation_beside_literal_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    request.state.__dict__["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_vars_state_mutation_beside_literal_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    state = request.state
    vars(state)["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_getattr_dict_mutation_beside_literal_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    getattr(request.state, "__dict__")["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_dict_attr_alias_mutation_beside_literal_cannot_authorize() -> None:
    """``d = request.state.__dict__; d[field]=client`` must not authorize."""

    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    d = request.state.__dict__
    d["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_object_getattribute_dict_mutation_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    object.__getattribute__(request.state, "__dict__")["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_state_getattribute_dict_mutation_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    request.state.__getattribute__("__dict__")["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_operator_attrgetter_dict_mutation_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
import operator
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    operator.attrgetter("__dict__")(request.state)["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_tuple_unpack_state_escape_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    (s,) = (request.state,)
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_list_unpack_state_escape_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    [s] = [request.state]
    s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_walrus_dict_mutation_beside_literal_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    (d := request.state.__dict__)["bypass_filter"] = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_for_iter_state_pack_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    for s in [request.state]:
        s.bypass_filter = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_list_append_state_escape_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    bucket = []
    bucket.append(request.state)
    bucket[0].bypass_filter = bypass_filter
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_rebound_writer_helper_cannot_authorize_via_stale_def() -> None:
    """Module-level ``write_state = other`` must not close over the original def."""

    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = True
write_state = evil_writer
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_tuple_unpack_writer_rebinding_cannot_authorize_via_stale_def() -> None:
    """``(write_state,) = (evil,)`` must not keep the original def identity."""

    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = True
(write_state,) = (evil_writer,)
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_list_unpack_writer_rebinding_cannot_authorize_via_stale_def() -> None:
    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = True
[write_state] = [evil_writer]
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_unknown_helper_receiving_state_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    external_mutate(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_unknown_method_receiving_request_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    request.app.dependency_overrides.clear()
    helper.configure(request)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_literal_only_helper_passthrough_still_authorizes() -> None:
    """Resolved local callee with only literal write may still authorize."""

    findings = analyze_bypass_authority(
        """
def mark_trusted(state):
    state.bypass_filter = True

def handler(request):
    mark_trusted(request.state)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "authorized"


def test_cross_module_helper_state_formal_cannot_authorize() -> None:
    findings = analyze_bypass_authority_unit(
        {
            "app/helpers.py": """
def write_state(state, value):
    state.bypass_filter = value
""".strip(),
            "app/routes.py": """
def write_state(state, value):
    state.bypass_filter = value

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/helpers.py", "app/routes.py"),
    )
    # Caller-local ``write_state`` resolves; client value still violates.
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_external_import_same_leaf_as_unrelated_local_cannot_authorize() -> None:
    """External ``write_state`` must not close over an unrelated local def."""

    findings = analyze_bypass_authority_unit(
        {
            "app/local_helpers.py": """
def write_state(state, value):
    state.bypass_filter = True
""".strip(),
            "app/routes.py": """
from thirdparty_package import write_state

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/local_helpers.py", "app/routes.py"),
    )
    assert findings[0].status == "unknown"


def test_local_import_uniquely_resolved_to_exact_implementation() -> None:
    """``from helpers import write_state`` follows the unique local body."""

    findings = analyze_bypass_authority_unit(
        {
            "app/helpers.py": """
def write_state(state, value):
    state.bypass_filter = value
""".strip(),
            "app/routes.py": """
from helpers import write_state

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/helpers.py", "app/routes.py"),
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"
    assert findings[0].write_count >= 2


def test_same_module_def_then_external_import_overwrite_cannot_authorize() -> None:
    """``def write_state`` then ``from external import write_state`` → import wins."""

    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = True
from thirdparty_package import write_state
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_local_import_then_assignment_overwrite_cannot_authorize() -> None:
    findings = analyze_bypass_authority_unit(
        {
            "app/helpers.py": """
def write_state(state, value):
    state.bypass_filter = True
""".strip(),
            "app/routes.py": """
from helpers import write_state
write_state = wrapper
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/helpers.py", "app/routes.py"),
    )
    assert findings[0].status == "unknown"


def test_module_alias_call_h_write_state_resolves_or_unknown() -> None:
    """``import helpers as h; h.write_state(...)`` follows unique module attr."""

    findings = analyze_bypass_authority_unit(
        {
            "app/helpers.py": """
def write_state(state, value):
    state.bypass_filter = value
""".strip(),
            "app/routes.py": """
import helpers as h

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    h.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/helpers.py", "app/routes.py"),
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_ambiguous_same_module_path_across_source_roots_is_unknown() -> None:
    findings = analyze_bypass_authority_unit(
        {
            "backend/helpers.py": """
def write_state(state, value):
    state.bypass_filter = True
""".strip(),
            "src/helpers.py": """
def write_state(state, value):
    state.bypass_filter = True
""".strip(),
            "app/routes.py": """
from helpers import write_state

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope(
            "backend/helpers.py",
            "src/helpers.py",
            "app/routes.py",
        ),
    )
    assert findings[0].status == "unknown"


def test_unimported_same_named_function_elsewhere_never_resolves() -> None:
    findings = analyze_bypass_authority_unit(
        {
            "app/helpers.py": """
def write_state(state, value):
    state.bypass_filter = True
""".strip(),
            "app/routes.py": """
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/helpers.py", "app/routes.py"),
    )
    assert findings[0].status == "unknown"


def test_import_alias_ws_resolves_unique_implementation() -> None:
    """``from helpers import write_state as ws; ws(...)`` follows unique body."""

    findings = analyze_bypass_authority_unit(
        {
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
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/helpers.py", "app/routes.py"),
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_relative_import_resolves_unique_implementation() -> None:
    findings = analyze_bypass_authority_unit(
        {
            "pkg/helpers.py": """
def write_state(state, value):
    state.bypass_filter = value
""".strip(),
            "pkg/sub/routes.py": """
from ..helpers import write_state

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="pkg/sub/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("pkg/helpers.py", "pkg/sub/routes.py"),
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_package_init_reexport_follows_implementation() -> None:
    findings = analyze_bypass_authority_unit(
        {
            "app/helpers/impl.py": """
def write_state(state, value):
    state.bypass_filter = value
""".strip(),
            "app/helpers/__init__.py": "from app.helpers.impl import write_state\n",
            "app/routes.py": """
from app.helpers import write_state

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope(
            "app/helpers/impl.py",
            "app/helpers/__init__.py",
            "app/routes.py",
        ),
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_same_leaf_different_packages_follows_imported_package() -> None:
    """``pkg_a`` safe leaf must not authorize a ``pkg_b`` import."""

    findings = analyze_bypass_authority_unit(
        {
            "pkg_a/helpers.py": """
def write_state(state, value):
    state.bypass_filter = True
""".strip(),
            "pkg_b/helpers.py": """
def write_state(state, value):
    state.bypass_filter = value
""".strip(),
            "app/routes.py": """
from pkg_b.helpers import write_state

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        },
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope(
            "pkg_a/helpers.py",
            "pkg_b/helpers.py",
            "app/routes.py",
        ),
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"
    assert findings[0].write_count >= 2


def test_circular_import_resolves_unique_writer_or_unknown() -> None:
    findings = analyze_bypass_authority_unit(
        {
            "app/a.py": """
from app.b import write_state

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
            "app/b.py": """
from app.a import handler

def write_state(state, value):
    state.bypass_filter = value
""".strip(),
        },
        entry_path="app/a.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("app/a.py", "app/b.py"),
    )
    assert findings[0].status == "violated"
    assert findings[0].reason == "client_controlled_bypass_write"


def test_getattr_module_write_state_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    getattr(helpers, "write_state")(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_importlib_dynamic_callee_cannot_authorize() -> None:
    findings = analyze_bypass_authority(
        """
import importlib
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    importlib.import_module("helpers").write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_class_method_named_write_state_never_resolves_as_module_fn() -> None:
    findings = analyze_bypass_authority(
        """
class Helpers:
    def write_state(self, state, value):
        state.bypass_filter = True

def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status == "unknown"


def test_nested_function_named_write_state_does_not_use_module_def() -> None:
    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = True

def handler(request, bypass_filter=False):
    def write_state(state, value):
        state.bypass_filter = value
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_for_loop_rebinding_cannot_authorize_via_stale_def() -> None:
    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = True
for write_state in [evil_writer]:
    pass
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_with_as_rebinding_cannot_authorize_via_stale_def() -> None:
    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = True
with CM() as write_state:
    pass
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_except_as_rebinding_cannot_authorize_via_stale_def() -> None:
    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = True
try:
    raise Exception()
except Exception as write_state:
    pass
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_match_pattern_rebinding_cannot_authorize_via_stale_def() -> None:
    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = True
match 1:
    case write_state:
        pass
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_del_rebinding_cannot_authorize_via_stale_def() -> None:
    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = True
del write_state
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_star_import_after_def_cannot_authorize_via_stale_def() -> None:
    """Star import may overwrite ``write_state``; closed-world also incomplete."""

    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = True
from evil import *
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_module_walrus_rebinding_cannot_authorize_via_stale_def() -> None:
    findings = analyze_bypass_authority(
        """
def write_state(state, value):
    state.bypass_filter = True
(write_state := evil_writer)
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope("<module>"),
        function_name="handler",
    )
    assert findings[0].status != "authorized"


def test_pe_compile_refuses_established_for_state_helper_client_write() -> None:
    files = {
        "app/middleware.py": """
def write_state(state, value):
    state.bypass_filter = value

def attach_trusted(request):
    request.state.bypass_filter = True
""".strip(),
        "app/routes.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    attach_trusted(request)
    write_state(request.state, bypass_filter)
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip(),
    }
    # Routes imports are unresolved unless helpers are inlined for PE compile;
    # put both writers in the route module for the PE surface check.
    files = {
        "app/routes.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

def write_state(state, value):
    state.bypass_filter = value

def attach_trusted(request):
    request.state.bypass_filter = True

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    attach_trusted(request)
    write_state(request.state, bypass_filter)
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip(),
    }
    profile = FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_parameter="user",
    )
    materials = AuthMaterials(
        base_files=files,
        head_files=files,
        repo="example/escape-bypass",
        base_revision="base",
        head_revision="head",
        repository_python_files=files,
    )
    ir = FastApiDependencyEffectExtractor().compile(materials, profile)
    assert ir.bypass_authority_evidence
    assert all(
        item.status != "established" for item in ir.bypass_authority_evidence
    )
