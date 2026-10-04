"""Executed-expression effect closure on PE CF positions (#173).

Side effects in executed control-flow expressions must be included in the PE
execution theorem via one shared observer ``_observe_executed_expression``:

``If.test``, ``While.test``, ``For.iter``, ``AsyncFor.iter``,
``With`` / ``AsyncWith.context_expr``, ``Match.subject``, ``MatchCase.guard``.

Closes false PASSes where setattr / zero-arg callable-identity mutators /
nested BoolOp / IfExp / walrus call effects in those positions were omitted
from writer closure or request-time identity scanning.

Unknown > false PASS. Held-out FormalPR partitions are not frozen.
"""

from __future__ import annotations

import sys

import pytest

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


def test_if_setattr_in_test_never_authorized() -> None:
    """1. if setattr(request.state, field, client) → never authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if setattr(request.state, "bypass_filter", bypass_filter):
        pass
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}
    assert findings[0].reason != "source_proved_server_authority_write"


def test_while_setattr_in_test_never_authorized() -> None:
    """2. while setattr(...) → never authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    while setattr(request.state, "bypass_filter", bypass_filter):
        break
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}
    assert findings[0].reason != "source_proved_server_authority_write"


def test_if_zero_arg_poison_in_test_later_helper_unknown() -> None:
    """3. zero-arg poison() in if test → later helper UNKNOWN."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return False
    if poison():
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_if_nested_boolop_poison_in_test() -> None:
    """4. nested flag and poison() test."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False, flag=False):
    def poison():
        helpers.write_state = evil
        return False
    if flag and poison():
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_if_conditional_expr_containing_mutator() -> None:
    """5. conditional expression containing mutator call."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False, flag=False):
    def poison():
        helpers.write_state = evil
        return False
    if (poison() if flag else False):
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_for_mutate_and_return_iter() -> None:
    """6. for _ in mutate_and_return_iter(...):"""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    def mutate_and_return_iter(state, value):
        setattr(state, "bypass_filter", value)
        return []
    request.state.bypass_filter = True
    for _ in mutate_and_return_iter(request.state, bypass_filter):
        pass
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}
    assert findings[0].reason != "source_proved_server_authority_write"


def test_for_zero_arg_callable_identity_mutator_in_iter() -> None:
    """7. zero-arg callable-identity mutator in for iterable."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return []
    for _ in poison():
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_with_mutation_in_context_factory() -> None:
    """8. mutation in with context_factory(...)."""

    findings = _unit(
        """
import helpers
from contextlib import nullcontext
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def context_factory():
        helpers.write_state = evil
        return nullcontext()
    with context_factory():
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_match_mutation_in_subject() -> None:
    """9. mutation in match SUBJECT."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return 0
    match poison():
        case _:
            pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_match_mutation_in_guarded_case() -> None:
    """10. mutation in guarded case _ if GUARD."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    match bypass_filter:
        case _ if setattr(request.state, "bypass_filter", bypass_filter):
            pass
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}
    assert findings[0].reason != "source_proved_server_authority_write"


def test_match_guard_zero_arg_identity_mutator_later_helper() -> None:
    """11. zero-arg callable identity mutator in match guard → later helper call."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return True
    match bypass_filter:
        case _ if poison():
            pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_walrus_containing_side_effecting_call() -> None:
    """12. walrus containing side-effecting call."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return False
    if (flag := poison()):
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_executed_expr_full_equals_incremental() -> None:
    """13. full vs incremental parity."""

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
    def poison():
        helpers.write_state = evil
        return False
    request.state.bypass_filter = True
    if setattr(request.state, "bypass_filter", bypass_filter):
        pass
    if poison():
        pass
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
            repo="example/executed-expression-effect-closure",
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


def test_e2e_pe_executed_expr_cannot_source_proved_authorize() -> None:
    """14. e2e PE: none yields established bypass evidence / source_proved unsoundly."""

    helpers = """
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    routes = """
from fastapi import Depends, FastAPI
import helpers
app = FastAPI()

def evil(state, value):
    state.bypass_filter = value

@app.post("/chat")
async def handler(request, bypass_filter: bool = False, user = Depends(get_current_user)):
    def poison():
        helpers.write_state = evil
        return False
    request.state.bypass_filter = True
    if setattr(request.state, "bypass_filter", bypass_filter):
        pass
    while setattr(request.state, "bypass_filter", bypass_filter):
        break
    for _ in (poison(),):
        pass
    match bypass_filter:
        case _ if poison():
            pass
    helpers.write_state(request.state, bypass_filter)
    if request.state.bypass_filter:
        return sink(user)
    return sink(user)
""".strip()
    repo = {
        "app/helpers.py": helpers + "\n",
        "app/routes.py": routes,
    }
    materials = AuthMaterials(
        base_files=dict(repo),
        head_files=dict(repo),
        repo="example/executed-expr-e2e",
        base_revision="base",
        head_revision="head",
        repository_python_files=repo,
        head_repository_python_files=repo,
        base_repository_python_files=repo,
    )
    profile = FastApiDependencyEffectProfile(
        sink_effects={"sink": "model.invoke"},
        sink_static_resources={"sink": "chat"},
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_parameter="user",
    )
    parsed = parse_head_python_materials(materials)
    contracts = build_contract_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    routes_idx = build_route_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )
    ir = FastApiDependencyEffectExtractor().compile(
        materials,
        profile,
        parsed_index=parsed,
        contract_summary_index=contracts,
        route_summary_index=routes_idx,
    )
    assert all(
        item.status != "established" for item in ir.bypass_authority_evidence
    )
    for item in ir.bypass_authority_evidence:
        assert item.reason != "source_proved_server_authority_write"


def test_pure_if_bool_config_flag_does_not_poison_identity() -> None:
    """15. positive: pure if bool(config_flag) does not unnecessarily poison identity."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, config_flag=False):
    if bool(config_flag):
        pass
    helpers.write_state(request.state, True)
    return request.state.bypass_filter
""",
        helpers=_helpers_source(body="True"),
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_benign_observational_calls_remain_acceptable() -> None:
    """16. positive: benign observational calls (len etc.) remain acceptable."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    if len(str(bypass_filter)) >= 0:
        pass
    if hasattr(request.state, "bypass_filter"):
        pass
    helpers.write_state(request.state, True)
    return request.state.bypass_filter
""",
        helpers=_helpers_source(body="True"),
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_if_unary_not_poison_never_authorized() -> None:
    """UnaryOp operand executes: ``if not poison()`` must not authorize."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return False
    if not poison():
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_if_compare_poison_never_authorized() -> None:
    """Compare operands execute: ``if poison() == False`` must not authorize."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return False
    if poison() == False:
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_if_subscript_index_poison_never_authorized() -> None:
    """Subscript index executes: ``if xs[poison()]`` must not authorize."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return 0
    xs = [False]
    if xs[poison()]:
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_if_fstring_poison_never_authorized() -> None:
    """JoinedStr values execute: ``if f'{poison()}'`` must not authorize."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return False
    if f'{poison()}':
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_while_unary_not_poison_never_authorized() -> None:
    """While.test UnaryOp operand must observe identity mutation."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return False
    while not poison():
        break
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_match_guard_unary_not_poison_never_authorized() -> None:
    """MatchCase.guard UnaryOp operand must observe identity mutation."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return True
    match bypass_filter:
        case _ if not poison():
            pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_compare_in_tuple_poison_never_authorized() -> None:
    """``if 0 in (poison(),)`` must not authorize."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return 0
    if 0 in (poison(),):
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_augassign_poison_rhs_never_authorized() -> None:
    """AugAssign RHS executes: ``x += poison()`` must not authorize."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return 0
    x = 0
    x += poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_assert_unary_not_poison_never_authorized() -> None:
    """Assert.test executes nested UnaryOp call effects."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return False
    assert not poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_raise_poison_never_authorized() -> None:
    """Raise.exc executes: ``raise poison()`` must not authorize."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return Exception('x')
    try:
        raise poison()
    except Exception:
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_except_type_poison_never_authorized() -> None:
    """except TYPE executes: ``except poison():`` must not authorize."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return Exception
    try:
        raise RuntimeError('x')
    except poison():
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_return_poison_arg_before_helper_write_never_authorized() -> None:
    """Return value executes args before callee: identity mutator then write."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return bypass_filter
    return helpers.write_state(request.state, poison()) or True
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_if_helper_call_with_poison_arg_never_authorized() -> None:
    """Same-expression arg-order: ``if write_state(state, poison())``."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return bypass_filter
    if helpers.write_state(request.state, poison()):
        pass
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_stmt_helper_call_with_poison_arg_never_authorized() -> None:
    """Statement call with arg-order identity mutator before write inlining."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return bypass_filter
    helpers.write_state(request.state, poison())
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_class_base_poison_never_authorized() -> None:
    """Class bases execute at definition: ``class C(poison())``."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return object
    class C(poison()):
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_class_metaclass_poison_never_authorized() -> None:
    """Class keywords execute: ``class C(metaclass=poison())``."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return type
    class C(metaclass=poison()):
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_class_name_decorator_poison_never_authorized() -> None:
    """``@poison`` on a nested class must follow the decorator call."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison(cls):
        helpers.write_state = evil
        return cls
    @poison
    class C:
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_setattr_in_nested_def_default_never_authorized() -> None:
    """Nested function defaults execute in the enclosing frame."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    def nested(x=setattr(request.state, "bypass_filter", bypass_filter)):
        return x
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}
    assert findings[0].reason != "source_proved_server_authority_write"


def test_setattr_in_class_base_never_authorized() -> None:
    """setattr in a class base must be a counted PE write."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    class C(setattr(request.state, "bypass_filter", bypass_filter) or object):
        pass
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}
    assert findings[0].reason != "source_proved_server_authority_write"


def test_nested_param_annotation_poison_never_authorized() -> None:
    """Parameter annotations evaluate at definition (no postponed eval)."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return bool
    def nested(x: poison() = True):
        return x
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_annotation_only_annassign_poison_never_authorized() -> None:
    """``x: poison()`` evaluates the annotation at runtime."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return bool
    x: poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_class_body_setattr_assign_never_authorized() -> None:
    """Class-body Assign executes: ``class C: x = setattr(state, ...)``."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    class C:
        x = setattr(request.state, "bypass_filter", bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}
    assert findings[0].reason != "source_proved_server_authority_write"


def test_class_body_expr_setattr_never_authorized() -> None:
    """Class-body Expr executes setattr at definition."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    class C:
        setattr(request.state, "bypass_filter", bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}
    assert findings[0].reason != "source_proved_server_authority_write"


def test_class_body_annassign_setattr_never_authorized() -> None:
    """Class-body AnnAssign value executes at definition."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    class C:
        x: object = setattr(request.state, "bypass_filter", bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}
    assert findings[0].reason != "source_proved_server_authority_write"


def test_method_default_setattr_never_authorized() -> None:
    """Method defaults execute during class-body definition."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    class C:
        def m(self, x=setattr(request.state, "bypass_filter", bypass_filter)):
            return x
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}
    assert findings[0].reason != "source_proved_server_authority_write"


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 type aliases require 3.12+")
def test_type_alias_poison_never_authorized() -> None:
    """``type X = poison()`` evaluates the value at definition."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return int
    type X = poison()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_unresolved_callee_kwarg_poison_never_authorized() -> None:
    """Imported callee kwargs execute: ``TypeVar('T', bound=poison())``."""

    findings = _unit(
        """
import helpers
from typing import TypeVar
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return int
    T = TypeVar('T', bound=poison())
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_imported_ctor_kwarg_poison_never_authorized() -> None:
    """``OrderedDict(a=poison())`` must observe keyword actuals."""

    findings = _unit(
        """
import helpers
from collections import OrderedDict
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return 1
    OrderedDict(a=poison())
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_starred_kwarg_poison_never_authorized() -> None:
    """``OrderedDict(**poison())`` must observe **kwargs actuals."""

    findings = _unit(
        """
import helpers
from collections import OrderedDict
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return {'a': 1}
    OrderedDict(**poison())
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 type params require 3.12+")
def test_pep695_type_param_bound_poison_never_authorized() -> None:
    """PEP 695 ``def nested[T: poison()]`` evaluates the bound."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return int
    def nested[T: poison()](x: T = True):
        return x
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_lambda_default_poison_never_authorized() -> None:
    """Lambda defaults execute at definition: ``f = lambda x=poison(): x``."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return 0
    f = lambda x=poison(): x
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_lambda_expr_stmt_default_poison_never_authorized() -> None:
    """Bare ``(lambda x=poison(): x)`` still evaluates defaults."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return 0
    (lambda x=poison(): x)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_lambda_default_in_if_test_poison_never_authorized() -> None:
    """``if (lambda x=poison(): x):`` must observe default identity effects."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return 0
    if (lambda x=poison(): x):
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_nested_lambda_default_poison_never_authorized() -> None:
    """Outer default that is itself a lambda must evaluate inner defaults."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return 0
    f = lambda x=(lambda y=poison(): y): x
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_setattr_in_lambda_default_never_authorized() -> None:
    """setattr in a lambda default is a counted PE write at definition."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    f = lambda x=setattr(request.state, "bypass_filter", bypass_filter): x
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}
    assert findings[0].reason != "source_proved_server_authority_write"


def test_ifexp_test_poison_never_authorized() -> None:
    """IfExp.test executes: ``if (False if poison() else False):``."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return False
    if (False if poison() else False):
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_boolop_packed_callee_poison_never_authorized() -> None:
    """``(poison() or len)("x")`` evaluates Call.func packing."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
        return len
    (poison() or len)("x")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_walrus_lambda_callee_poison_never_authorized() -> None:
    """``(f := (lambda: poison()))()`` follows NamedExpr-packed callee."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    (f := (lambda: poison()))()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_list_subscript_lambda_callee_poison_never_authorized() -> None:
    """``[lambda: poison()][0]()`` follows packed lambda callee."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    [lambda: poison()][0]()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_lambda_starargs_body_poison_never_authorized() -> None:
    """``lambda *a: poison(); f()`` follows vararg lambda bodies."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    f = lambda *a: poison()
    f()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_lambda_default_to_call_poison_never_authorized() -> None:
    """Default-to-call: ``lambda x=(lambda: poison()): x(); f()``."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def poison():
        helpers.write_state = evil
    f = lambda x=(lambda: poison()): x()
    f()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_nested_def_export_rebind_evil_never_authorized() -> None:
    """Nested FunctionDef assigned to helpers.write_state must not use original."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    def evil(state, value):
        state.bypass_filter = value
    helpers.write_state = evil
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"
    assert findings[0].status in {"violated", "unknown"}


def test_nested_def_export_rebind_annassign_never_authorized() -> None:
    """AnnAssign rebind of helpers.write_state to nested evil."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    def evil(state, value):
        state.bypass_filter = value
    helpers.write_state: object = evil
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_nested_def_export_rebind_tuple_unpack_never_authorized() -> None:
    """Tuple-unpack rebind of helpers.write_state to nested evil."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    def evil(state, value):
        state.bypass_filter = value
    (helpers.write_state,) = (evil,)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_del_request_state_field_never_authorized() -> None:
    """``del request.state.bypass_filter`` after literal server write."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    del request.state.bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_del_request_state_field_in_if_never_authorized() -> None:
    """``del`` in if body after literal server write."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    if True:
        del request.state.bypass_filter
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_local_metaclass_prepare_never_authorized() -> None:
    """Local metaclass ``__prepare__``/``__new__`` fail closed / observed."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Meta:
        @classmethod
        def __prepare__(cls, name, bases):
            helpers.write_state = evil
            return {}
        def __new__(cls, name, bases, ns):
            helpers.write_state = evil
            return type.__new__(cls, name, bases, ns)
    class C(metaclass=Meta):
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_init_subclass_poison_never_authorized() -> None:
    """Base ``__init_subclass__`` runs on subclassing — fail closed / observed."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    class C(Base):
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_types_new_class_exec_body_never_authorized() -> None:
    """``types.new_class(..., exec_body=body)`` observes exec_body."""

    findings = _unit(
        """
import helpers
import types
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def body(ns):
        helpers.write_state = evil
    types.new_class("C", (), {}, body)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_exec_string_poison_never_authorized() -> None:
    """Request-time ``exec`` of helper-mutating code fail closed."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    exec("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_matchclass_local_metaclass_never_authorized() -> None:
    """MatchClass against local metaclass ``__instancecheck__`` fail closed."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Meta(type):
        def __instancecheck__(self, obj):
            helpers.write_state = evil
            return True
    class Box(metaclass=Meta):
        pass
    match object():
        case Box():
            pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_aliased_base_init_subclass_never_authorized() -> None:
    """``Alias = Base; class C(Alias)`` must observe ``__init_subclass__``."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    Alias = Base
    class C(Alias):
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_builtins_exec_as_run_never_authorized() -> None:
    """``from builtins import exec as run; run(...)`` fail closed."""

    findings = _unit(
        """
import helpers
from builtins import exec as run
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    run("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_builtins_dot_exec_never_authorized() -> None:
    """``builtins.exec(...)`` fail closed."""

    findings = _unit(
        """
import helpers
import builtins
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    builtins.exec("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_getattr_builtins_exec_never_authorized() -> None:
    """``getattr(builtins, "exec")(...)`` fail closed."""

    findings = _unit(
        """
import helpers
import builtins
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    getattr(builtins, "exec")("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_types_as_t_new_class_never_authorized() -> None:
    """``import types as t; t.new_class(..., body)`` observes exec_body."""

    findings = _unit(
        """
import helpers
import types as t
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def body(ns):
        helpers.write_state = evil
    t.new_class("C", (), {}, body)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_assert_msg_walrus_closure_never_authorized() -> None:
    """Assert.msg walrus callable product must be observed before ``fn()``."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def mid():
        def poison():
            helpers.write_state = evil
        return poison
    try:
        assert False, (fn := mid())
    except AssertionError:
        pass
    fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_raise_cause_walrus_closure_never_authorized() -> None:
    """Raise.cause walrus callable product must be observed before ``fn()``."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def mid():
        def poison():
            helpers.write_state = evil
        return poison
    try:
        raise Exception("x") from (fn := mid())
    except Exception:
        pass
    fn()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_for_attr_export_rebind_never_authorized() -> None:
    """``for helpers.write_state in [evil]`` must poison later helper resolve."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    for helpers.write_state in [evil]:
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_with_as_attr_export_rebind_never_authorized() -> None:
    """``with CM() as helpers.write_state`` must poison later helper resolve."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class CM:
        def __enter__(self):
            return evil
        def __exit__(self, *a):
            return False
    with CM() as helpers.write_state:
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_mut_init_ifexp_test_never_authorized() -> None:
    """Local ``Mut().__init__`` identity poison in IfExp.test must observe."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    if (False if Mut() else False):
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_mut_init_call_func_never_authorized() -> None:
    """Local ``Mut()`` in Call.func IfExp arm must observe ``__init__``."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    (len if Mut() else len)("x")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_mut_init_lambda_default_never_authorized() -> None:
    """Local ``Mut()`` in lambda default must observe ``__init__``."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    f = lambda x=Mut(): x
    f()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_nested_local_import_affects_closed_world() -> None:
    """Nested ``import other.missing`` must make closed-world incomplete."""

    from ovk.compilers.authorization.bypass_authority import (
        _evaluate_closed_world,
    )

    files = {
        "app/helpers.py": _helpers_source(),
        "app/routes.py": """
import helpers
def handler(request, bypass_filter=False):
    import other.missing
    request.state.bypass_filter = True
    return request.state.bypass_filter
""".strip(),
        "app/other.py": "Y = 1\n",
    }
    cw = _evaluate_closed_world(
        files,
        scope_proof=_scope(
            "app/helpers.py",
            "app/routes.py",
            "app/other.py",
            import_roots=("app",),
        ),
    )
    assert cw.complete is False
    assert any("other.missing" in item for item in cw.unresolvable_imports)


def test_positive_if_bool_config_still_authorized() -> None:
    """Spot-check: pure ``if bool(config_flag)`` still authorizes."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False, config_flag=True):
    request.state.bypass_filter = True
    if bool(config_flag):
        pass
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_positive_len_hasattr_still_authorized() -> None:
    """Spot-check: ``len`` / ``hasattr`` observers still authorize."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    request.state.bypass_filter = True
    len("x")
    hasattr(request, "state")
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_positive_unused_lambda_body_still_authorized() -> None:
    """Spot-check: unused lambda body does not poison authority."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    def poison():
        pass
    f = lambda: poison()
    request.state.bypass_filter = True
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "authorized"
    assert findings[0].reason == "source_proved_server_authority_write"


def test_packed_mut_construction_shapes_never_authorized() -> None:
    """Packed/Attribute/inherited/factory ``Mut()`` must observe ``__init__``."""

    for snippet in (
        "(Mut if True else int)()",
        "(False or Mut)()",
        "[Mut][0]()",
        '{"M":Mut}["M"]()',
        "(m:=Mut)()",
        "Holder.Mut()",
        "class Child(Mut):\n        pass\n    Child()",
        "def factory():\n        return Mut\n    factory()()",
    ):
        findings = _unit(
            f"""
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    class Holder:
        Mut = Mut
    {snippet}
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        )
        assert findings[0].status != "authorized", snippet
        assert findings[0].reason != "source_proved_server_authority_write", snippet


def test_for_with_unpack_export_rebind_never_authorized() -> None:
    """Tuple/List/Starred for/with-as export rebinds recurse like Assign."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    for (helpers.write_state,) in [(evil,)]:
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class CM:
        def __enter__(self):
            return (evil,)
        def __exit__(self, *a):
            return False
    with CM() as (helpers.write_state,):
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_local_exec_new_class_and_type_protocols_never_authorized() -> None:
    """Local exec/new_class rebinds, type(), match-as, __set_name__, projections."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    run = exec
    run("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import types
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def body(ns):
        helpers.write_state = evil
    nc = types.new_class
    nc("C", (), {}, body)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    type("C", (Base,), {})
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    match Base:
        case x:
            class C(x):
                pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Desc:
        def __set_name__(self, owner, name):
            helpers.write_state = evil
    class C:
        x = Desc()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import builtins
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    vars(builtins)["exec"]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    list(map(exec, ["helpers.write_state = evil"]))
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_third_pass_class_exec_protocol_shapes_never_authorized() -> None:
    """getattr/walrus/packed/type/__set_name__/itemgetter protocol shapes."""

    for routes in (
        """
import helpers
import builtins
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    run = getattr(builtins, "exec")
    run("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import types
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def body(ns):
        helpers.write_state = evil
    g = getattr
    g(types, "new_class")("C", (), {}, body)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    (run := exec)("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import types
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    def body(ns):
        helpers.write_state = evil
    (nc := types.new_class)("C", (), {}, body)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    T = type
    T("C", (Base,), {})
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import builtins
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    builtins.type("C", (Base,), {})
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    type("C", bases=(Base,), dict={})
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Desc:
        def __set_name__(self, owner, name):
            helpers.write_state = evil
    d = Desc()
    class C:
        x = d
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import builtins
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    operator.itemgetter("exec")(vars(builtins))("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    [exec][0]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_third_pass_identity_construction_shapes_never_authorized() -> None:
    """getattr/attrgetter/vars/__call__/classmethod/map Mut construction."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Holder:
        class Mut:
            def __init__(self):
                helpers.write_state = evil
    getattr(Holder, "Mut")()
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
    vars()["Mut"]()
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
    Mut.__call__()
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
    type.__call__(Mut)
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
        @classmethod
        def make(cls):
            return cls()
    Mut.make()
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
    list(map(lambda c: c(), [Mut]))
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_third_pass_interproc_and_cf_packed_protocols_never_authorized() -> None:
    """Match/comprehension Attribute rebinds and CF packed protocol callees."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    match (evil,):
        case (helpers.write_state,):
            pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    [0 for helpers.write_state in [evil]]
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {0 for helpers.write_state in [evil]}
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    if (exec if True else len)("helpers.write_state = evil"):
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    while (False or exec)("helpers.write_state = evil"):
        break
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {"e": exec}["e"]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    (type if True else int)("C", (Base,), {})
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_fourth_pass_shared_peel_exec_shapes_never_authorized() -> None:
    """Shared Call peel: .get/.pop/next(iter)/getattr packs/operator.call/MPT."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {"e":exec}.get("e")("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    [exec].pop()("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {exec}.pop()("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    next(iter([exec]))("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import builtins
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    [getattr(builtins,"exec")][0]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import builtins
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    (getattr(builtins, "exec") if True else len)("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import builtins
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    (False or getattr(builtins, "exec"))("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    operator.call(exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    vars().get("exec")("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import builtins
from types import MappingProxyType
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    MappingProxyType(vars(builtins))["exec"]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import builtins
from operator import itemgetter as ig
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    ig("exec")(vars(builtins))("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    (x := {"e": exec}.get("e"))("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_fourth_pass_identity_construction_peels_never_authorized() -> None:
    """attrgetter/getitem/methodcaller/partial/getattr(__call__)/type.__new__."""

    for routes in (
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Holder:
        class Mut:
            def __init__(self):
                helpers.write_state = evil
    operator.attrgetter("Mut")(Holder)()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from operator import attrgetter as ag
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Holder:
        class Mut:
            def __init__(self):
                helpers.write_state = evil
    ag("Mut")(Holder)()
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
    {"Mut":Mut}.get("Mut")()
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
    d = {"Mut": Mut}
    d.get("Mut")()
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
    {}.get("missing", Mut)()
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
    getattr(Mut,"__call__")()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    operator.attrgetter("__call__")(Mut)()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    operator.methodcaller("__call__")(Mut)()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    operator.getitem({"Mut": Mut}, "Mut")()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import functools
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    functools.partial(Mut)()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    type.__new__(type, "C", (Base,), {})
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    object.__class__.__new__(type, "C", (Base,), {})
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_fourth_pass_cross_module_proxy_adapter_never_authorized() -> None:
    """``from helpers import Proxy`` after ``Proxy = MappingProxyType``."""

    files = {
        "app/helpers.py": """
from types import MappingProxyType
Proxy = MappingProxyType
def write_state(state, value):
    state.bypass_filter = True
""".strip(),
        "app/routes.py": """
from helpers import Proxy
import helpers
def handler(request, bypass_filter=False):
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
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
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_fourth_pass_module_annassign_adapter_never_authorized() -> None:
    """Module AnnAssign ``Proxy: object = MPT`` seeds adapter aliases."""

    findings = _unit(
        """
import helpers
from types import MappingProxyType as MPT
Proxy: object = MPT
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_fourth_pass_getattr_mappingproxy_alias_never_authorized() -> None:
    """``Proxy = getattr(types, \"MappingProxyType\")`` seeds adapter alias."""

    findings = _unit(
        """
import helpers
import types
def handler(request, bypass_filter=False):
    Proxy = getattr(types, "MappingProxyType")
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_fifth_pass_operator_call_name_aliases_never_authorized() -> None:
    """Name-bound ``call as oc`` / assign / walrus / getattr before Name short-circuit."""

    for routes in (
        """
import helpers
from operator import call as oc
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    oc(exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    oc = operator.call
    oc(exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    (oc := operator.call)(exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    oc = getattr(operator, "call")
    oc(exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_fifth_pass_module_projection_and_factory_products_never_authorized() -> None:
    """Module getitem/partial seeds; Name-bound attrgetter/partial/itemgetter products."""

    for routes in (
        """
import helpers
from operator import getitem as gi
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    gi({"Mut": Mut}, "Mut")()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from functools import partial as p
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    p(Mut)()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from operator import attrgetter as agf
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Holder:
        class Mut:
            def __init__(self):
                helpers.write_state = evil
    ag = agf("Mut")
    ag(Holder)()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from functools import partial as pf
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    p = pf(Mut)
    p()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from operator import itemgetter as igf
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    ig = igf("Mut")
    ig({"Mut": Mut})()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from operator import methodcaller as mcf
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def poison(self):
            helpers.write_state = evil
    mc = mcf("poison")
    mc(Mut())
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_fifth_pass_adapter_getattr_vars_dict_peels_never_authorized() -> None:
    """Renamed/builtins.getattr, vars/__dict__, packed Proxy Call.func peels."""

    for routes in (
        """
import helpers
import types
def handler(request, bypass_filter=False):
    g = getattr
    Proxy = g(types, "MappingProxyType")
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import types
import builtins
def handler(request, bypass_filter=False):
    Proxy = builtins.getattr(types, "MappingProxyType")
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import types
def handler(request, bypass_filter=False):
    Proxy = vars(types)["MappingProxyType"]
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import types
def handler(request, bypass_filter=False):
    Proxy = types.__dict__["MappingProxyType"]
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from types import MappingProxyType
def handler(request, bypass_filter=False):
    Proxy = MappingProxyType
    s = (Proxy if True else dict)({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from types import MappingProxyType
def handler(request, bypass_filter=False):
    Proxy = MappingProxyType
    s = (False or Proxy)({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from types import MappingProxyType
def handler(request, bypass_filter=False):
    s = (Proxy := MappingProxyType)({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from types import MappingProxyType
def handler(request, bypass_filter=False):
    Proxy = MappingProxyType
    s = [Proxy][0]({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_fifth_pass_type_protocol_and_match_class_bind_never_authorized() -> None:
    """getattr/packed type.__new__/__call__, object.__class__.__call__, match C bind."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    getattr(type, "__new__")(type, "C", (Base,), {})
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
    getattr(type, "__call__")(Mut)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    [getattr(type, "__new__")][0](type, "C", (Base,), {})
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
    object.__class__.__call__(Mut)
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
    match Mut:
        case C:
            C()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_sixth_pass_packed_operator_call_and_type_protocol_never_authorized() -> None:
    """Packed call/next/subscript/methodcaller + Name-bound type protocol."""

    for routes in (
        """
import helpers
from operator import call as oc
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    [oc][0](exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from operator import call as oc
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    next(iter([oc]))(exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from operator import call as oc, methodcaller
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    methodcaller("__call__", exec, "helpers.write_state = evil")(oc)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    [(oc := operator.call)][0](exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    next(iter([getattr(operator, "call")]))(exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    tn = type.__new__
    tn(type, "C", (Base,), {})
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
    tc = getattr(type, "__call__")
    tc(Mut)
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
        case (C,):
            C()
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
    match {"c": Mut}:
        case {"c": C}:
            C()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_sixth_pass_identity_projection_products_never_authorized() -> None:
    """Intermediate Name-bound getitem/.get/partial.__call__ products."""

    for routes in (
        """
import helpers
from operator import getitem as gi
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    m = gi({"Mut": Mut}, "Mut")
    m()
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
    d = {"Mut": Mut}
    m = d["Mut"]
    m()
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
    d = {"Mut": Mut}
    m = d.get("Mut")
    m()
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
    g = {}.get
    g("missing", Mut)()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from functools import partial as pf
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    p = pf(Mut)
    p.__call__()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from functools import partial as pf
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    p = pf(Mut)
    getattr(p, "__call__")()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_sixth_pass_adapter_dict_and_ns_alias_peels_never_authorized() -> None:
    """Dict-keyed Call.func, getattr(__dict__), renamed vars, .get MPT seeds."""

    for routes in (
        """
import helpers
from types import MappingProxyType as Proxy
def handler(request, bypass_filter=False):
    s = {"p": Proxy}["p"]({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from types import MappingProxyType as Proxy
def handler(request, bypass_filter=False):
    s = {0: Proxy}[0]({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from types import MappingProxyType as Proxy
def handler(request, bypass_filter=False):
    s = ({} | {"p": Proxy})["p"]({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import types
def handler(request, bypass_filter=False):
    Proxy = getattr(types, "__dict__")["MappingProxyType"]
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import types
def handler(request, bypass_filter=False):
    v = vars
    Proxy = v(types)["MappingProxyType"]
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import types
def handler(request, bypass_filter=False):
    Proxy = types.__dict__.get("MappingProxyType")
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import types
def handler(request, bypass_filter=False):
    Proxy = vars(types).get("MappingProxyType")
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_seventh_pass_operator_call_attr_and_dict_packs_never_authorized() -> None:
    """oc.__call__/getattr/dict() kwargs/Name-bound itemgetter/type.__call__ packs."""

    for routes in (
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    oc = operator.call
    oc.__call__(exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    oc = operator.call
    getattr(oc, "__call__")(exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    operator.call.__call__(exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    oc = operator.call
    d = oc.__call__
    d(exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    dict(e=exec)["e"]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    dict(**{"e": exec})["e"]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from operator import itemgetter
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    oc = operator.call
    ig = itemgetter(0)
    ig([oc])(exec, "helpers.write_state = evil")
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
    next(iter([type.__call__]))(Mut)
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
    type.__call__.__call__(Mut)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    tn = type.__new__
    [tn][0](type, "C", (Base,), {})
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
    g = dict.get
    g({}, "missing", Mut)()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import functools
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    p = getattr(functools, "partial")(Mut)
    p()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from functools import partial as pf
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    (p := pf(Mut)).__call__()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from types import MappingProxyType as Proxy
def handler(request, bypass_filter=False):
    d = {"p": Proxy}
    s = d["p"]({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from types import MappingProxyType as Proxy
def handler(request, bypass_filter=False):
    s = dict(p=Proxy)["p"]({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import types
def handler(request, bypass_filter=False):
    Proxy = getattr(types.__dict__, "get")("MappingProxyType")
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
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
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    match {"c": Mut}:
        case {"c": C, **rest}:
            C()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_seventh_pass_nested_import_install_never_authorized() -> None:
    """Accounted nested ``import pkg.nested as n; n.install(evil)`` export rebind."""

    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    files = {
        "app/helpers.py": _helpers_source(),
        "app/pkg/__init__.py": "",
        "app/pkg/nested.py": nested,
        "app/routes.py": """
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    n.install(evil)
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""".strip(),
    }
    findings = analyze_bypass_authority_unit(
        files,
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope(*files, import_roots=("app",)),
    )
    assert findings[0].status != "authorized"
    assert findings[0].reason != "source_proved_server_authority_write"


def test_eighth_pass_alias_ns_view_getitem_pop_never_authorized() -> None:
    """getattr(ns, \"__getitem__\"|\"pop\") MappingProxy seeds (shared ns views)."""

    for routes in (
        """
import helpers
import types
def handler(request, bypass_filter=False):
    Proxy = getattr(types.__dict__, "__getitem__")("MappingProxyType")
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import types
def handler(request, bypass_filter=False):
    Proxy = getattr(vars(types), "__getitem__")("MappingProxyType")
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import types
def handler(request, bypass_filter=False):
    Proxy = getattr(types.__dict__, "pop")("MappingProxyType")
    s = Proxy({"s": request.state})["s"]
    s.bypass_filter = bypass_filter
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_eighth_pass_dict_ctor_merge_and_adapters_never_authorized() -> None:
    """Name-bound dict/__call__/builtins/|/`|=`/OrderedDict/map/filter packs."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    D = dict
    D(e=exec)["e"]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    dict.__call__(e=exec)["e"]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import builtins
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    getattr(builtins, "dict")(e=exec)["e"]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    ({} | {"e": exec})["e"]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    d = {}
    d |= {"e": exec}
    d["e"]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from collections import OrderedDict
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    OrderedDict(e=exec)["e"]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from collections import UserDict
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    UserDict(e=exec)["e"]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
from types import SimpleNamespace
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    SimpleNamespace(e=exec).e("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    dict.fromkeys(["e"], exec)["e"]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    oc = operator.call
    next(map(lambda x: x, [oc]))(exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    oc = operator.call
    next(filter(None, [oc]))(exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_eighth_pass_match_rest_and_protocol_binds_never_authorized() -> None:
    """MatchMapping rest packs + Match Name exec/type/operator.call identity."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    match {"c": Mut}:
        case {**rest}:
            rest["c"]()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    match {"e": exec}:
        case {"e": e}:
            e("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    match (exec,):
        case (*xs,):
            xs[0]("helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    tn = type.__new__
    match {"t": tn}:
        case {"t": t}:
            t(type, "C", (Base,), {})
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import operator
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    oc = operator.call
    match {"o": oc}:
        case {**rest}:
            rest["o"](exec, "helpers.write_state = evil")
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_eighth_pass_type_protocol_and_dict_view_products_never_authorized() -> None:
    """tc.__call__/tn.__call__/D.get/builtins.dict.get identity products."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    tc = type.__call__
    tc.__call__(Mut)
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
    (tc := type.__call__).__call__(Mut)
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Base:
        def __init_subclass__(cls, **kw):
            helpers.write_state = evil
    tn = type.__new__
    tn.__call__(type, "C", (Base,), {})
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
    tc = type.__call__
    d = tc.__call__
    d(Mut)
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
    D = dict
    g = D.get
    g({}, "missing", Mut)()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import builtins
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    g = builtins.dict.get
    g({}, "missing", Mut)()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
import builtins
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    g = builtins.dict.pop
    g({"m": Mut}, "m")()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_eighth_pass_lexical_unpack_with_and_star_never_authorized() -> None:
    """Assign unpack / with-as constructor / star pack class seeds."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Cls:
        def __init__(self):
            helpers.write_state = evil
    C, = [Cls]
    C()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Cls:
        def __init__(self):
            helpers.write_state = evil
    [C] = [Cls]
    C()
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
    class CM:
        def __enter__(self):
            return Mut
        def __exit__(self, *a):
            return False
    with CM() as M:
        M()
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
    *xs, = [Mut]
    xs[0]()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_eighth_pass_for_class_seed_iter_variety_never_authorized() -> None:
    """For class seeds via dict views / comps / star packs / genexps."""

    for routes in (
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    class Mut:
        def __init__(self):
            helpers.write_state = evil
    for C in {"c": Mut}.values():
        C()
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
    for C in {Mut: 1}.keys():
        C()
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
    for k, C in {"c": Mut}.items():
        C()
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
    *xs, = [Mut]
    for C in xs:
        C()
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
    for C in [x for x in [Mut]]:
        C()
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
    for C in (x for x in [Mut]):
        C()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        findings = _unit(routes)
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def test_eighth_pass_nested_import_install_peels_never_authorized() -> None:
    """getattr/__call__/list-pack/from-import nested install export rebinds."""

    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    for routes in (
        """
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    getattr(n, "install")(evil)
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    n.install.__call__(evil)
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    [n.install][0](evil)
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
        """
from pkg.nested import install
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    install(evil)
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
""",
    ):
        files = {
            "app/helpers.py": _helpers_source(),
            "app/pkg/__init__.py": "",
            "app/pkg/nested.py": nested,
            "app/routes.py": routes.strip(),
        }
        findings = analyze_bypass_authority_unit(
            files,
            entry_path="app/routes.py",
            function_name="handler",
            bypass_fields=frozenset({"bypass_filter"}),
            scope_proof=_scope(*files, import_roots=("app",)),
        )
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"


def _ninth_src(body: str, *, imports: str = "") -> str:
    """Build a handler source around ``body`` (indented one level by callers).

    ``Mut`` / ``Base`` are defined only when referenced; ``Mut()`` rebinds
    ``helpers.write_state`` to an attacker-controlled writer and ``Base``
    does the same from ``__init_subclass__``.
    """

    lines = ["import helpers", *([imports] if imports else [])]
    lines += [
        "def evil(state, value):",
        "    state.bypass_filter = value",
        "def handler(request, bypass_filter=False):",
    ]
    if "Mut" in body:
        lines += [
            "    class Mut:",
            "        def __init__(self):",
            "            helpers.write_state = evil",
        ]
    if "Base" in body:
        lines += [
            "    class Base:",
            "        def __init_subclass__(cls, **kw):",
            "            helpers.write_state = evil",
        ]
    lines += [f"    {ln}" if ln else ln for ln in body.strip("\n").split("\n")]
    lines += [
        "    helpers.write_state(request.state, bypass_filter)",
        "    return request.state.bypass_filter",
    ]
    return "\n".join(lines)


_NINTH_EXEC = '"helpers.write_state = evil"'


def _assert_ninth_not_authorized(cases: tuple[tuple[str, str], ...]) -> None:
    leaked: list[str] = []
    for body, imports in cases:
        findings = _unit(_ninth_src(body, imports=imports))
        if (
            findings[0].status == "authorized"
            or findings[0].reason == "source_proved_server_authority_write"
        ):
            leaked.append(body)
    assert not leaked, "false PASS for:\n" + "\n---\n".join(leaked)


def test_ninth_pass_match_subject_peel_class_and_protocol() -> None:
    """Match subjects (Name/walrus/dict()/``**``/non-constant keys) seed rest."""

    _assert_ninth_not_authorized(
        (
            ('d = {"c": Mut}\nmatch d:\n    case {**rest}:\n        rest["c"]()', ""),
            (
                'match (d := {"c": Mut}):\n    case {**rest}:\n        rest["c"]()',
                "",
            ),
            ('match dict(c=Mut):\n    case {**rest}:\n        rest["c"]()', ""),
            (
                'match {**{"c": Mut}}:\n    case {**rest}:\n        rest["c"]()',
                "",
            ),
            (
                'k = "c"\nmatch {k: Mut}:\n    case {**rest}:\n        rest["c"]()',
                "",
            ),
            (
                'match {"c": Mut}:\n    case {**rest}:\n        rest["c"].__call__()',
                "",
            ),
            (
                'extra = {"c": Mut}\nmatch {**extra}:\n    case {**rest}:\n'
                '        rest["c"]()',
                "",
            ),
            (
                'match {"a": 1, **{"c": Mut}}:\n    case {**rest}:\n'
                '        rest["c"]()',
                "",
            ),
            (
                'd = {"e": exec}\nmatch d:\n    case {**rest}:\n'
                f"        rest[\"e\"]({_NINTH_EXEC})",
                "",
            ),
            (
                'd = {"e": exec}\nmatch d:\n    case {**rest}:\n'
                f"        rest[\"e\"].__call__({_NINTH_EXEC})",
                "",
            ),
            (
                'match (d := {"e": exec}):\n    case {**rest}:\n'
                f"        rest[\"e\"]({_NINTH_EXEC})",
                "",
            ),
            (
                '{"e": exec}["e"].__call__(' + _NINTH_EXEC + ")",
                "",
            ),
            (
                'tn = type.__new__\nd = {"t": tn}\nmatch d:\n    case {**rest}:\n'
                '        rest["t"](type, "C", (Base,), {})',
                "",
            ),
            (
                'oc = operator.call\nmatch dict(o=oc):\n    case {**rest}:\n'
                f"        rest[\"o\"](exec, {_NINTH_EXEC})",
                "import operator",
            ),
            (
                'oc = operator.call\nmatch dict(o=oc):\n    case {**rest}:\n'
                f"        rest[\"o\"].__call__(exec, {_NINTH_EXEC})",
                "import operator",
            ),
            (
                f'xs = (exec,)\nmatch xs:\n    case (*r,):\n        r[0]({_NINTH_EXEC})',
                "",
            ),
        )
    )


def test_ninth_pass_alias_ns_name_bound_and_setdefault() -> None:
    """Name-bound namespace projections and ``setdefault`` view attr."""

    tail = (
        'Proxy = {proxy}\ns = Proxy({{"s": request.state}})["s"]\n'
        "s.bypass_filter = bypass_filter"
    )
    cases = (
        'ns = types.__dict__\nProxy = ns.get("MappingProxyType")\n'
        's = Proxy({"s": request.state})["s"]\ns.bypass_filter = bypass_filter',
        'ns = vars(types)\nProxy = ns.get("MappingProxyType")\n'
        's = Proxy({"s": request.state})["s"]\ns.bypass_filter = bypass_filter',
        'ns = types.__dict__\nProxy = ns["MappingProxyType"]\n'
        's = Proxy({"s": request.state})["s"]\ns.bypass_filter = bypass_filter',
        'ns = types.__dict__\nProxy = getattr(ns, "get")("MappingProxyType")\n'
        's = Proxy({"s": request.state})["s"]\ns.bypass_filter = bypass_filter',
        'ns = types.__dict__\n'
        'Proxy = getattr(ns, "__getitem__")("MappingProxyType")\n'
        's = Proxy({"s": request.state})["s"]\ns.bypass_filter = bypass_filter',
        'ns = vars(types)\nProxy = getattr(ns, "pop")("MappingProxyType")\n'
        's = Proxy({"s": request.state})["s"]\ns.bypass_filter = bypass_filter',
        tail.format(proxy='types.__dict__.setdefault("MappingProxyType")'),
        tail.format(proxy='vars(types).setdefault("MappingProxyType")'),
        tail.format(
            proxy='getattr(types.__dict__, "setdefault")("MappingProxyType")'
        ),
        'ns = types.__dict__\nProxy = ns.setdefault("MappingProxyType")\n'
        's = Proxy({"s": request.state})["s"]\ns.bypass_filter = bypass_filter',
    )
    _assert_ninth_not_authorized(tuple((c, "import types") for c in cases))


def test_ninth_pass_dict_ctor_merge_and_adapters_never_authorized() -> None:
    """defaultdict/ChainMap/Name-bound merge/operator or_/ior/comps/zip/update."""

    ex = _NINTH_EXEC
    plain = (
        f'defaultdict(None, {{"e": exec}})["e"]({ex})',
        f'defaultdict(e=exec)["e"]({ex})',
        f'ChainMap({{"e": exec}})["e"]({ex})',
        f'd = {{"e": exec}}\n(d | {{}})["e"]({ex})',
        f'd = {{"e": exec}}\n({{}} | d)["e"]({ex})',
        f'd = {{"e": exec}}\ne = d | {{}}\ne["e"]({ex})',
        f'd = {{"e": exec}}\ne = {{}} | d\ne["e"]({ex})',
        f'operator.or_({{}}, {{"e": exec}})["e"]({ex})',
        f'operator.ior({{}}, {{"e": exec}})["e"]({ex})',
        f'{{}}.__or__({{"e": exec}})["e"]({ex})',
        f'{{}}.__ior__({{"e": exec}})["e"]({ex})',
        f'd = {{"e": exec}}\nd.__or__({{}})["e"]({ex})',
        f'd = {{}}\nd.__ior__({{"e": exec}})["e"]({ex})',
        f'D = dict.__call__\nD(e=exec)["e"]({ex})',
        f'D = dict\nE = D.__call__\nE(e=exec)["e"]({ex})',
        f'd = {{"e": exec}}\ne = d["e"].__call__\ne({ex})',
        f'next(x for x in [exec])({ex})',
        f'[x for x in [exec]][0]({ex})',
        f'next(iter([x for x in [exec]]))({ex})',
        f'for _, f in enumerate([exec]):\n    f({ex})',
        f'for f, in zip([exec]):\n    f({ex})',
        f'next(zip([exec]))[0]({ex})',
        f'next(enumerate([exec]))[1]({ex})',
        f'd = {{}}\nd.update(e=exec)\nd["e"]({ex})',
        f'd = {{}}\nd.update({{"e": exec}})\nd["e"]({ex})',
        f'd = {{}}\nd.setdefault("e", exec)\nd["e"]({ex})',
        f'd = {{"e": exec}}\nd.copy()["e"]({ex})',
        f'd = {{"e": exec}}\nc = d.copy()\nc["e"]({ex})',
        f'd = {{"e": exec}}\ndict(d)["e"]({ex})',
        f'{{"e": exec}}.copy()["e"]({ex})',
    )
    cases = [(c, "from collections import ChainMap, defaultdict\nimport operator") for c in plain]
    _assert_ninth_not_authorized(tuple(cases))
    oc_cases = (
        f'oc = operator.call\nfor f in zip([oc]):\n    f[0](exec, {ex})',
        f'oc = operator.call\nfor _, f in enumerate([oc]):\n    f(exec, {ex})',
    )
    _assert_ninth_not_authorized(tuple((c, "import operator") for c in oc_cases))


def test_ninth_pass_interproc_for_dict_view_seeds_never_authorized() -> None:
    """Name/walrus/getattr/DictComp dict-view For seeds + class construction."""

    _assert_ninth_not_authorized(
        (
            ('d = {"c": Mut}\nfor C in d.values():\n    C()', ""),
            ('for C in (d := {"c": Mut}).values():\n    C()', ""),
            ('d = {Mut: 1}\nfor C in d.keys():\n    C()', ""),
            ('d = {"c": Mut}\nfor k, C in d.items():\n    C()', ""),
            ('for C in getattr({"c": Mut}, "values")():\n    C()', ""),
            ('d = {"c": Mut}\nfor C in getattr(d, "values")():\n    C()', ""),
            ('for k, C in {k: Mut for k in ["c"]}.items():\n    C()', ""),
            ('for C in {k: Mut for k in ["c"]}.values():\n    C()', ""),
            ('for C in dict(c=Mut).values():\n    C()', ""),
            ('for C in {"c": Mut}.copy().values():\n    C()', ""),
        )
    )


def test_ninth_pass_nested_import_install_peels_never_authorized() -> None:
    """``n.install.__call__`` / getattr.__call__ / packed install peels."""

    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    for call in (
        "n.install.__call__(evil)",
        'getattr(n, "install").__call__(evil)',
        '[getattr(n, "install")][0](evil)',
        "next(iter([n.install]))(evil)",
        "next(iter([n.install])).__call__(evil)",
        "(f := n.install)(evil)",
        "{'i': n.install}['i'](evil)",
    ):
        routes = f"""
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {call}
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        files = {
            "app/helpers.py": _helpers_source(),
            "app/pkg/__init__.py": "",
            "app/pkg/nested.py": nested,
            "app/routes.py": routes.strip(),
        }
        findings = analyze_bypass_authority_unit(
            files,
            entry_path="app/routes.py",
            function_name="handler",
            bypass_fields=frozenset({"bypass_filter"}),
            scope_proof=_scope(*files, import_roots=("app",)),
        )
        assert findings[0].status != "authorized", call
        assert findings[0].reason != "source_proved_server_authority_write", call


def test_ninth_pass_type_protocol_nested_call_and_dict_view_products() -> None:
    """Nested ``tc.__call__`` / match-rest / for / map; setdefault; vars(builtins)."""

    cases = (
        'tc = type.__call__\n(d := tc.__call__)(Mut)',
        'd = (tc := type.__call__).__call__\nd(Mut)',
        'tc = type.__call__\nd = (e := tc.__call__)\nd(Mut)',
        'type.__call__.__call__(Mut)',
        'tc = type.__call__\ngetattr(tc, "__call__")(Mut)',
        'getattr(type.__call__, "__call__")(Mut)',
        'tc = type.__call__\nd = getattr(tc, "__call__")\nd(Mut)',
        'tc = type.__call__\nfor f in [tc.__call__]:\n    f(Mut)',
        'tc = type.__call__\nfor f in [tc]:\n    f.__call__(Mut)',
        'tc = type.__call__\nnext(map(lambda x: x, [tc.__call__]))(Mut)',
        'tc = type.__call__\nmatch {"t": tc}:\n    case {**rest}:\n        rest["t"].__call__(Mut)',
        'tc = type.__call__\nmatch {"t": tc.__call__}:\n    case {"t": t}:\n        t(Mut)',
        'tc = type.__call__\nmatch {"t": tc.__call__}:\n    case {**rest}:\n        rest["t"](Mut)',
        'tn = type.__new__\ntn.__call__.__call__(type, "C", (Base,), {})',
        'tn = type.__new__\nfor f in [tn.__call__]:\n    f(type, "C", (Base,), {})',
        'D = dict\ng = D.setdefault\ng({}, "m", Mut)()',
        'g = dict.setdefault\ng({}, "m", Mut)()',
        'g = builtins.dict.setdefault\ng({}, "m", Mut)()',
        'g = vars(builtins)["dict"].get\ng({}, "missing", Mut)()',
        'g = builtins.__dict__["dict"].get\ng({}, "missing", Mut)()',
        'g = vars(builtins).get("dict").get\ng({}, "missing", Mut)()',
        'g = vars(builtins)["dict"].setdefault\ng({}, "m", Mut)()',
        'ns = vars(builtins)\ng = ns["dict"].get\ng({}, "missing", Mut)()',
    )
    _assert_ninth_not_authorized(tuple((c, "import builtins") for c in cases))


def test_ninth_pass_lexical_keys_values_unpack_never_authorized() -> None:
    """Assign/star unpack from ``.keys()``/``.values()``/``.items()`` + match rest."""

    _assert_ninth_not_authorized(
        (
            ('C, = {Mut: 1}.keys()\nC()', ""),
            ('[C] = {Mut: 1}.keys()\nC()', ""),
            ('C, = {"c": Mut}.values()\nC()', ""),
            ('*xs, = {Mut: 1}.keys()\nxs[0]()', ""),
            ('*xs, = {"c": Mut}.values()\nxs[0]()', ""),
            ('(k, C), = {"c": Mut}.items()\nC()', ""),
            ('C, = {Mut: 1}\nC()', ""),
            ('d = {Mut: 1}\nC, = d.keys()\nC()', ""),
            ('C, = list({Mut: 1}.keys())\nC()', ""),
            ('C, = ({} | {Mut: 1}).keys()\nC()', ""),
            (
                "class CM:\n"
                "    def __enter__(self):\n"
                "        return {Mut: 1}.keys()\n"
                "    def __exit__(self, *a):\n"
                "        return False\n"
                "with CM() as ks:\n"
                "    C, = ks\n"
                "    C()",
                "",
            ),
            (
                "class CM:\n"
                "    def __enter__(self):\n"
                "        return {Mut: 1}\n"
                "    def __exit__(self, *a):\n"
                "        return False\n"
                "with CM() as d:\n"
                "    C, = d.keys()\n"
                "    C()",
                "",
            ),
            ('match {"c": Mut}:\n    case {**rest}:\n        for C in rest.values():\n            C()', ""),
            ('match {"c": Mut}:\n    case {**rest}:\n        for k, C in rest.items():\n            C()', ""),
            ('match {"c": Mut}:\n    case {**rest}:\n        C, = rest.values()\n        C()', ""),
            ('match {Mut: 1}:\n    case {**rest}:\n        C, = rest.keys()\n        C()', ""),
            ('match {Mut: 1}:\n    case {**rest}:\n        for C in rest.keys():\n            C()', ""),
            ('match {"c": Mut}:\n    case {**rest}:\n        (k, C), = rest.items()\n        C()', ""),
        )
    )


def test_ninth_pass_positive_authorized_smoke() -> None:
    """Benign analogues of the ninth-pass shapes remain authorized."""

    for body in (
        'd = {"c": int}\nmatch d:\n    case {**rest}:\n        rest["c"]()',
        'ns = types.__dict__\nProxy = ns.get("MappingProxyType")\nProxy({})',
        'D = dict.__call__\nD(e=len)["e"]("x")',
        'C, = {int: 1}.keys()\nC()',
    ):
        src = (
            "import helpers\nimport types\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status == "authorized", body
        assert findings[0].reason == "source_proved_server_authority_write", body


def test_tenth_pass_trailing_call_and_map_apply_never_authorized() -> None:
    """Trailing ``.__call__`` after adapters; map applies construction in lambda."""

    _assert_ninth_not_authorized(
        (
            ("tc = type.__call__\nnext(iter([tc.__call__])).__call__(Mut)", ""),
            ("tc = type.__call__\nnext(iter([tc])).__call__(Mut)", ""),
            (
                "tc = type.__call__\nnext(reversed([tc.__call__])).__call__(Mut)",
                "",
            ),
            (
                "tc = type.__call__\np = [tc.__call__]\nnext(iter(p)).__call__(Mut)",
                "",
            ),
            (
                "tc = type.__call__\nlist(map(lambda f: f(Mut), [tc.__call__]))",
                "",
            ),
            (
                'tn = type.__new__\n'
                'getattr(tn, "__call__").__call__(type, "C", (Base,), {})',
                "",
            ),
            (
                'tc = type.__call__\ngetattr(tc, "__call__").__call__(Mut)',
                "",
            ),
            ("next(iter([Mut])).__call__()", ""),
            (
                'tn = type.__new__\nnext(iter([tn])).__call__(type, "C", (Base,), {})',
                "",
            ),
            ("Mut.__call__.__call__()", ""),
            (
                'match {"c": Mut}:\n    case {**rest}:\n'
                '        rest["c"].__call__.__call__()',
                "",
            ),
            (
                'tn = type.__new__\nmatch {"t": tn}:\n    case {**rest}:\n'
                '        getattr(rest["t"], "__call__").__call__('
                'type, "C", (Base,), {})',
                "",
            ),
        )
    )


def test_tenth_pass_walrus_setdefault_and_alias_ns_never_authorized() -> None:
    """Walrus as Call.func for setdefault; ns-view ``.__call__`` / Name key."""

    _assert_ninth_not_authorized(
        (
            ('D = dict\n(g := D.setdefault)({}, "m", Mut)()', "import builtins"),
            ('(g := dict.setdefault)({}, "m", Mut)()', "import builtins"),
            (
                '(g := vars(builtins)["dict"].setdefault)({}, "m", Mut)()',
                "import builtins",
            ),
        )
    )
    alias_imports = "import types"
    cases = (
        'ns = types.__dict__\n'
        'Proxy = getattr(ns, "setdefault").__call__("MappingProxyType")\n'
        's = Proxy({"s": request.state})["s"]\ns.bypass_filter = bypass_filter',
        'ns = types.__dict__\n'
        'Proxy = getattr(ns, "get").__call__("MappingProxyType")\n'
        's = Proxy({"s": request.state})["s"]\ns.bypass_filter = bypass_filter',
        'ns = types.__dict__\nk = "MappingProxyType"\n'
        'Proxy = getattr(ns, "setdefault")(k)\n'
        's = Proxy({"s": request.state})["s"]\ns.bypass_filter = bypass_filter',
        'match {"p": types.MappingProxyType}:\n'
        '    case {**rest}:\n'
        '        s = rest["p"]({"s": request.state})["s"]\n'
        "        s.bypass_filter = bypass_filter",
    )
    _assert_ninth_not_authorized(tuple((c, alias_imports) for c in cases))


def test_tenth_pass_cf_mapping_projection_never_authorized() -> None:
    """AugAssign/getattr merge, Counter/ChainMap/copy/update/popitem/setitem/itertools."""

    ex = _NINTH_EXEC
    imp = (
        "from collections import ChainMap, Counter, defaultdict\n"
        "import copy, operator, itertools"
    )
    plain = (
        f'getattr({{}}, "__or__")({{"e": exec}})["e"]({ex})',
        f'getattr({{}}, "__ior__")({{"e": exec}})["e"]({ex})',
        f'getattr({{"e": exec}}, "__ror__")({{}})["e"]({ex})',
        f'Counter({{"e": exec}})["e"]({ex})',
        f'cm = ChainMap({{"e": exec}})\ncm.maps[0]["e"]({ex})',
        f'ChainMap().new_child({{"e": exec}})["e"]({ex})',
        f'd = {{"e": exec}}\ncopy.copy(d)["e"]({ex})',
        f'd = {{"e": exec}}\ncopy.deepcopy(d)["e"]({ex})',
        f'd = {{}}\ndict.update(d, e=exec)\nd["e"]({ex})',
        'd = {}\ngetattr(d, "update")(e=exec)\nd["e"](' + ex + ")",
        f'd = {{}}\nu = d.update\nu(e=exec)\nd["e"]({ex})',
        f'k, f = {{"e": exec}}.popitem()\nf({ex})',
        f'd = {{}}\noperator.setitem(d, "e", exec)\nd["e"]({ex})',
        f'for f in itertools.chain([exec]):\n    f({ex})',
        f'for f in itertools.islice([exec], 1):\n    f({ex})',
    )
    _assert_ninth_not_authorized(tuple((c, imp) for c in plain))


def test_tenth_pass_lexical_name_views_fromkeys_popitem_never_authorized() -> None:
    """Name-bound items/fromkeys/AugAssign keys/next(iter)/popitem packing."""

    _assert_ninth_not_authorized(
        (
            ('it = {"c": Mut}.items()\n(k, C), = it\nC()', ""),
            ('it = {"c": Mut}.items()\nfor k, C in it:\n    C()', ""),
            (
                "class CM:\n"
                "    def __enter__(self):\n"
                '        return {"c": Mut}.items()\n'
                "    def __exit__(self, *a):\n"
                "        return False\n"
                "with CM() as it:\n"
                "    (k, C), = it\n"
                "    C()",
                "",
            ),
            ("C, = dict.fromkeys([Mut])\nC()", ""),
            ("*xs, = dict.fromkeys([Mut])\nxs[0]()", ""),
            ("for C in dict.fromkeys([Mut]):\n    C()", ""),
            ("d = {Mut: 1}\nd |= {}\nC, = d.keys()\nC()", ""),
            ("C = next(iter({Mut: 1}.keys()))\nC()", ""),
            ('k, C = {"c": Mut}.popitem()\nC()', ""),
            (
                'match {"c": Mut}:\n    case {**rest}:\n'
                "        k, C = rest.popitem()\n        C()",
                "",
            ),
            (
                "with ({Mut: 1}.keys()) as ks:\n    C, = ks\n    C()",
                "",
            ),
            ('d = {Mut: 1}\nk = d.keys\nfor C in k():\n    C()', ""),
            ('d = {"c": Mut}\nv = d.values\nfor C in v():\n    C()', ""),
        )
    )


def test_tenth_pass_interproc_name_install_never_authorized() -> None:
    """Name-bound / list-packed install peels (``f.__call__`` / ``fns[0]``)."""

    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    for call in (
        "f = n.install\n    f.__call__(evil)",
        "f = n.install.__call__\n    f(evil)",
        "fns = [n.install]\n    fns[0](evil)",
    ):
        routes = f"""
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {call}
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        files = {
            "app/helpers.py": _helpers_source(),
            "app/pkg/__init__.py": "",
            "app/pkg/nested.py": nested,
            "app/routes.py": routes.strip(),
        }
        findings = analyze_bypass_authority_unit(
            files,
            entry_path="app/routes.py",
            function_name="handler",
            bypass_fields=frozenset({"bypass_filter"}),
            scope_proof=_scope(*files, import_roots=("app",)),
        )
        assert findings[0].status != "authorized", call
        assert findings[0].reason != "source_proved_server_authority_write", call


def test_tenth_pass_positive_authorized_smoke() -> None:
    """Benign analogues of the tenth-pass shapes remain authorized."""

    for body in (
        "tc = type.__call__\nnext(iter([tc])).__call__(int)",
        'D = dict\n(g := D.setdefault)({}, "m", int)()',
        "C, = dict.fromkeys([int])\nC()",
        'd = {}\nd |= {"e": len}\nd["e"]("x")',
        'ns = types.__dict__\nk = "MappingProxyType"\n'
        'Proxy = getattr(ns, "setdefault")(k)\nProxy({})',
    ):
        src = (
            "import helpers\nimport types\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status == "authorized", body
        assert findings[0].reason == "source_proved_server_authority_write", body


def test_eleventh_pass_identity_higher_order_apply_never_authorized() -> None:
    """filter/comp/genexp/any/all/sum/map/reduce/starmap/key= type.__call__."""

    _assert_ninth_not_authorized(
        (
            ("list(filter(lambda f: f(Mut) or True, [type.__call__]))", ""),
            ("any(f(Mut) for f in [type.__call__])", ""),
            ("all(f(Mut) or True for f in [type.__call__])", ""),
            ("sum(1 for f in [type.__call__] if f(Mut) or True)", ""),
            ("[f(Mut) for f in [type.__call__]]", ""),
            ("{f(Mut) for f in [type.__call__]}", ""),
            ("{i: f(Mut) for i, f in enumerate([type.__call__])}", ""),
            ("(lambda f: f(Mut))(type.__call__)", ""),
            ("(lambda f, *a: f(Mut))(type.__call__)", ""),
            ("(lambda f, **k: f(Mut))(type.__call__)", ""),
            ("(lambda f=type.__call__: f(Mut))()", ""),
            (
                'getattr(type, "__new__").__call__(type, "C", (Base,), {})',
                "",
            ),
            ("list(map(lambda t: t(Mut), [type]))", ""),
            ('list(map(lambda t: t(Mut), {"c": type}.values()))', ""),
            (
                "from functools import reduce\n"
                "reduce(lambda a, f: f(Mut) or a, [type.__call__], 0)",
                "from functools import reduce",
            ),
            (
                "import itertools\n"
                "list(itertools.starmap(lambda f: f(Mut), [(type.__call__,)]))",
                "import itertools",
            ),
            ("sorted([type.__call__], key=lambda f: f(Mut) or 0)", ""),
            ("max([type.__call__], key=lambda f: f(Mut) or 0)", ""),
            ("min([type.__call__], key=lambda f: f(Mut) or 0)", ""),
        )
    )


def test_eleventh_pass_class_method_call_peel_never_authorized() -> None:
    """``Mut.make.__call__()`` / getattr / next(iter) / match-rest peels."""

    cases = (
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
Mut.make.__call__()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @staticmethod
    def smake():
        helpers.write_state = evil
Mut.smake.__call__()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    def poke(self):
        helpers.write_state = evil
m = Mut.__new__(Mut)
m.poke.__call__()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
next(iter([Mut.make])).__call__()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
match {"m": Mut.make}:
    case {**rest}:
        rest["m"].__call__()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
getattr(Mut, "make").__call__()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
fns = [Mut.make]
fns[0].__call__()
""".strip(),
    )
    for body in cases:
        src = (
            "import helpers\n"
            "def evil(state, value):\n"
            "    state.bypass_filter = value\n"
            "def handler(request, bypass_filter=False):\n"
            + "\n".join(f"    {ln}" if ln else ln for ln in body.split("\n"))
            + "\n    helpers.write_state(request.state, bypass_filter)\n"
            "    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_eleventh_pass_lexical_name_views_and_fromkeys_never_authorized() -> None:
    """Dict-literal items Name, fromkeys Name, next(iter), copy.keys, popitem."""

    _assert_ninth_not_authorized(
        (
            ('g={"c":Mut}.items; (k,C),=g(); C()', ""),
            ("fk=dict.fromkeys; C,=fk([Mut]); C()", ""),
            (
                "fk=dict.fromkeys\nwith fk([Mut]) as ks:\n    C,=ks\n    C()",
                "",
            ),
            ("C=next(iter({Mut:1})); C()", ""),
            ('d={Mut:1}; d|={}; C,=copy.copy(d).keys(); C()', "import copy"),
            ('k,C=dict.popitem({"c":Mut}); C()', ""),
            ('k,C=getattr(dict,"popitem")({"c":Mut}); C()', ""),
            (
                'match {"c":Mut}:\n    case {**rest}:\n'
                "        C=list(rest.items())[0][1]; C()",
                "",
            ),
        )
    )


def test_eleventh_pass_alias_ns_bound_view_trusted_write_first() -> None:
    """Trusted-write-first ns get/Name-key/walrus/itemgetter must not authorize."""

    alias_imports = "import types"
    cases = (
        'ns=types.__dict__\n'
        'Proxy=getattr(ns,"get").__call__((k:="MappingProxyType"))\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'g=getattr(ns,"get")\n'
        'Proxy=g("MappingProxyType")\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        "g=ns.get\n"
        'Proxy=g("MappingProxyType")\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'k="MappingProxyType"\n'
        "Proxy=ns[k]\n"
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys=["MappingProxyType"]\n'
        'Proxy=getattr(ns,"get")(keys[0])\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'Proxy=getattr(getattr(ns,"get"),"__call__")("MappingProxyType")\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
    )
    for body in cases:
        src = (
            "import helpers\n"
            f"{alias_imports}\n"
            "def evil(state, value):\n"
            "    state.bypass_filter = value\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_eleventh_pass_cf_itertools_and_packs_never_authorized() -> None:
    """Expanded itertools adapters, getattr copy/setitem, ChainMap, packs."""

    ex = _NINTH_EXEC
    imp = (
        "from collections import ChainMap, deque\n"
        "import copy, operator, itertools, types"
    )
    plain = (
        f"ch=itertools.chain\nfor f in ch([exec]):\n    f({ex})",
        f"for f in itertools.chain_from_iterable([[exec]]):\n    f({ex})",
        f"for f in itertools.starmap(lambda x: x, [(exec,)]):\n    f({ex})",
        f"for f in itertools.compress([exec], [1]):\n    f({ex})",
        f"for f in itertools.filterfalse(lambda x: False, [exec]):\n    f({ex})",
        f"for f in itertools.dropwhile(lambda x: False, [exec]):\n    f({ex})",
        f"for f in itertools.takewhile(lambda x: True, [exec]):\n    f({ex})",
        f"a,b=itertools.tee([exec])\nfor f in a:\n    f({ex})",
        f"for f in itertools.zip_longest([exec]):\n    f[0]({ex})",
        f"for f in itertools.cycle([exec]):\n    f({ex})\n    break",
        f"for f in itertools.repeat(exec, 1):\n    f({ex})",
        f"for t in itertools.permutations([exec], 1):\n    t[0]({ex})",
        f"for t in itertools.combinations([exec], 1):\n    t[0]({ex})",
        f"for t in itertools.product([exec]):\n    t[0]({ex})",
        f'getattr(operator,"setitem")({{}}, "e", exec)["e"]({ex})',
        f'd={{"e":exec}}\ngetattr(copy,"copy")(d)["e"]({ex})',
        f'd={{"e":exec}}\ngetattr(copy,"deepcopy")(d)["e"]({ex})',
        f'cm=ChainMap({{"e":exec}})\ncm.parents[0]["e"]({ex})',
        f'cm=ChainMap()\ncm.maps.append({{"e":exec}})\ncm["e"]({ex})',
        f'ns=types.SimpleNamespace(e=exec)\nns.e({ex})',
        f"xs=[]\nxs+=[exec]\nxs[0]({ex})",
        f"s=set()\ns.update([exec])\nlist(s)[0]({ex})",
        f"for f in deque([exec]):\n    f({ex})",
    )
    _assert_ninth_not_authorized(tuple((c, imp) for c in plain))


def test_eleventh_pass_interproc_name_view_and_install_never_authorized() -> None:
    """Name-bound keys with/for, packed BoundMethod views, install packs."""

    _assert_ninth_not_authorized(
        (
            ("d={Mut:1}\nk=d.keys; C=next(iter(k())); C()", ""),
            (
                'd={"c":Mut}\nk=d.values\nwith k() as ks:\n    C,=ks\n    C()',
                "",
            ),
            (
                "d={Mut:1}\nk=d.keys\nwith k() as ks:\n    C,=ks\n    C()",
                "",
            ),
            ("d={Mut:1}\nviews=[d.keys]\nfor C in views[0]():\n    C()", ""),
        )
    )
    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    for call in (
        "fns={0:n.install}\n    fns[0](evil)",
        "fns={0:n.install}\n    xs=list(fns.values())\n    xs[0](evil)",
        "for f in [n.install]:\n        f(evil)",
        "match [n.install]:\n        case [f]:\n            f(evil)",
        "(lambda f: f(evil))(n.install)",
    ):
        routes = f"""
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {call}
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        files = {
            "app/helpers.py": _helpers_source(),
            "app/pkg/__init__.py": "",
            "app/pkg/nested.py": nested,
            "app/routes.py": routes.strip(),
        }
        findings = analyze_bypass_authority_unit(
            files,
            entry_path="app/routes.py",
            function_name="handler",
            bypass_fields=frozenset({"bypass_filter"}),
            scope_proof=_scope(*files, import_roots=("app",)),
        )
        assert findings[0].status != "authorized", call
        assert findings[0].reason != "source_proved_server_authority_write", call


def test_eleventh_pass_positive_authorized_smoke() -> None:
    """Benign analogues of the eleventh-pass shapes remain authorized."""

    for body in (
        "list(map(lambda t: t(int), [type]))",
        "C=next(iter({int:1})); C()",
        "fk=dict.fromkeys; C,=fk([int]); C()",
        'd={}\nd|={"e": len}\nd["e"]("x")',
        'ns=types.__dict__\ng=getattr(ns,"get")\nProxy=g("MappingProxyType")\nProxy({})',
    ):
        src = (
            "import helpers\nimport types\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status == "authorized", body
        assert findings[0].reason == "source_proved_server_authority_write", body


def test_twelfth_pass_lexical_copy_name_augassign_never_authorized() -> None:
    """copy/deepcopy/getattr/dict()/d.copy into Name then |= preserves packs."""

    _assert_ninth_not_authorized(
        (
            (
                "d={Mut:1}\ne=copy.copy(d)\ne|={}\nC,=e.keys()\nC()",
                "import copy",
            ),
            (
                "d={Mut:1}\ne=copy.deepcopy(d)\ne|={}\nC,=e.keys()\nC()",
                "import copy",
            ),
            (
                'd={Mut:1}\ne=getattr(copy,"copy")(d)\ne|={}\nC,=e.keys()\nC()',
                "import copy",
            ),
            ("d={Mut:1}\ne=dict(d)\ne|={}\nC,=e.keys()\nC()", ""),
            ("d={Mut:1}\ne=d.copy()\ne|={}\nC,=e.keys()\nC()", ""),
            (
                'd={"c":Mut}\ne=copy.copy(d)\ne|={}\nC,=e.values()\nC()',
                "import copy",
            ),
            (
                'd={"c":Mut}\ne=copy.copy(d)\ne|={}\nk,C=e.popitem()\nC()',
                "import copy",
            ),
            (
                "d={Mut:1}\ne=copy.copy(d)\ne|={}\nfor C in e.keys():\n    C()",
                "import copy",
            ),
            (
                "d={Mut:1}\ne=copy.copy(d)\ne|={}\nC,=*e.keys(),\nC()",
                "import copy",
            ),
            (
                "d={Mut:1}\ne=copy.copy(d)\ne|={}\n"
                "with e.keys() as ks:\n    C,=ks\n    C()",
                "import copy",
            ),
        )
    )


def test_twelfth_pass_identity_inverted_key_starmap_never_authorized() -> None:
    """key=/starmap type.__call__ / Name/getattr / builtins / star-kw / walrus."""

    _assert_ninth_not_authorized(
        (
            ("sorted([Mut], key=type.__call__)", ""),
            ("k=type.__call__\nsorted([Mut], key=k)", ""),
            ('sorted([Mut], key=getattr(type,"__call__"))', ""),
            ('sorted({"m":Mut}.values(), key=type.__call__)', ""),
            ("max([Mut], key=type.__call__)", ""),
            ("min([Mut], key=type.__call__)", ""),
            ("xs=[Mut]\nxs.sort(key=type.__call__)", ""),
            (
                "import itertools\n"
                "list(itertools.starmap(type.__call__, [(Mut,)]))",
                "import itertools",
            ),
            (
                "from itertools import starmap as sm\n"
                "list(sm(type.__call__, [(Mut,)]))",
                "from itertools import starmap as sm",
            ),
            (
                'from functools import reduce\n'
                'getattr(__import__("functools"),"reduce")'
                "(lambda a, f: f(Mut) or a, [type.__call__], 0)",
                "from functools import reduce",
            ),
            ("(lambda f: f(Mut))(*[type.__call__])", ""),
            (
                '(lambda **k: list(k.values())[0](Mut))(**{"f": type.__call__})',
                "",
            ),
            (
                'next(iter([getattr(type,"__new__")])).__call__('
                'type, "C", (object,), {})',
                "",
            ),
            (
                "import builtins\n"
                "builtins.max([type.__call__], key=lambda f: f(Mut) or 0)",
                "import builtins",
            ),
            (
                "import builtins\n"
                "builtins.sorted([Mut], key=type.__call__)",
                "import builtins",
            ),
            ("list(map(lambda t: t(Mut), [(t:=type)]))", ""),
        )
    )


def test_twelfth_pass_alias_name_bound_key_never_authorized() -> None:
    """``k=keys[0]`` / dict keys after indirection must not authorize."""

    alias_imports = "import types"
    cases = (
        'ns=types.__dict__\n'
        'keys=["MappingProxyType"]\n'
        "k=keys[0]\n"
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys=["MappingProxyType"]\n'
        "k=keys[0]\n"
        "Proxy=ns[k]\n"
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys=["MappingProxyType"]\n'
        "k=keys[0]\n"
        "g=ns.get\n"
        "Proxy=g(k)\n"
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys=["MappingProxyType"]\n'
        "k=keys[0]\n"
        'view=getattr(ns,"get")\n'
        'Proxy=getattr(view,"__call__")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys={"x":"MappingProxyType"}\n'
        'Proxy=getattr(ns,"get")(keys["x"])\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
    )
    for body in cases:
        src = (
            "import helpers\n"
            f"{alias_imports}\n"
            "def evil(state, value):\n"
            "    state.bypass_filter = value\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_twelfth_pass_cf_itertools_inplace_ns_never_authorized() -> None:
    """Real from_iterable, new adapters, iadd/ior, ChainMap maps, ns assign."""

    ex = _NINTH_EXEC
    imp = (
        "from collections import ChainMap\n"
        "import operator, itertools, types"
    )
    plain = (
        f"for f in itertools.chain.from_iterable([[exec]]):\n    f({ex})",
        f'for f in getattr(itertools,"chain")([exec]):\n    f({ex})',
        f'for f in getattr(itertools,"starmap")(lambda x: x, [(exec,)]):\n'
        f"    f({ex})",
        f'for f in getattr(itertools,"compress")([exec], [1]):\n    f({ex})',
        f'for f in getattr(itertools,"cycle")([exec]):\n    f({ex})\n    break',
        f'a,b=getattr(itertools,"tee")([exec])\nfor f in a:\n    f({ex})',
        f'for f in getattr(itertools,"repeat")(exec, 1):\n    f({ex})',
        f'for f in getattr(itertools,"chain").from_iterable([[exec]]):\n'
        f"    f({ex})",
        f"for _,g in itertools.groupby([exec]):\n    for f in g:\n        f({ex})",
        f"for f in itertools.accumulate([exec], lambda a,b: b):\n    f({ex})",
        f"for t in itertools.combinations_with_replacement([exec], 1):\n"
        f"    t[0]({ex})",
        f"for a,b in itertools.pairwise([exec, exec]):\n    a({ex})",
        f"for t in itertools.batched([exec], 1):\n    t[0]({ex})",
        f"xs=[]\noperator.iadd(xs, [exec])\nxs[0]({ex})",
        f"xs=[]\nxs.__iadd__([exec])\nxs[0]({ex})",
        f"xs=[]\nlist.__iadd__(xs, [exec])\nxs[0]({ex})",
        f"s=set()\noperator.ior(s, {{exec}})\nlist(s)[0]({ex})",
        f"s=set()\ns.__ior__({{exec}})\nlist(s)[0]({ex})",
        f'cm=ChainMap()\ncm.maps += [{{"e":exec}}]\ncm["e"]({ex})',
        f'cm=ChainMap()\ncm.maps.__iadd__([{{"e":exec}}])\ncm["e"]({ex})',
        f'cm=ChainMap({{}})\ncm.maps[0].update({{"e":exec}})\ncm["e"]({ex})',
        f'cm=ChainMap({{}})\ncm.maps[0]["e"]=exec\ncm["e"]({ex})',
        f"ns=types.SimpleNamespace()\nns.e=exec\nns.e({ex})",
    )
    _assert_ninth_not_authorized(tuple((c, imp) for c in plain))


def test_twelfth_pass_class_factory_bare_call_never_authorized() -> None:
    """``mk=Mut.make; mk()`` / walrus / __func__ / getattribute / NS packs."""

    cases = (
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
mk=Mut.make
mk()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
(mk:=Mut.make)()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
getattr(Mut.make,"__call__")()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
c=Mut.make.__call__
c()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
object.__getattribute__(Mut,"make").__call__()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
Mut.make.__func__(Mut)
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @staticmethod
    def smake():
        helpers.write_state = evil
Mut.smake.__func__()
""".strip(),
        """
import types
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
types.SimpleNamespace(m=Mut.make).m.__call__()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    def poke(self):
        helpers.write_state = evil
m=Mut.__new__(Mut)
packs=[m.poke]
for p in packs:
    p()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    def poke(self):
        helpers.write_state = evil
m=Mut.__new__(Mut)
packs={"p":m.poke}
next(iter(packs.values()))()
""".strip(),
    )
    for body in cases:
        src = (
            "import helpers\n"
            "def evil(state, value):\n"
            "    state.bypass_filter = value\n"
            "def handler(request, bypass_filter=False):\n"
            + "\n".join(f"    {ln}" if ln else ln for ln in body.split("\n"))
            + "\n    helpers.write_state(request.state, bypass_filter)\n"
            "    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_twelfth_pass_interproc_pack_depth_never_authorized() -> None:
    """Dict-packed BoundMethod / fromkeys packs / install installers."""

    _assert_ninth_not_authorized(
        (
            (
                "d={Mut:1}\nviews={'v':d.keys}\nfor C in views['v']():\n    C()",
                "",
            ),
            (
                "d={Mut:1}\nviews=[d.keys]\nnext(iter(views))()\n"
                "C,=views[0]()\nC()",
                "",
            ),
            (
                "d={Mut:1}\nviews=[d.keys]\n"
                "getattr(views[0],'__call__')()\n"
                "C,=list(views[0]())\nC()",
                "",
            ),
            ("d={Mut:1}\nk=d.keys\nC=list(k())[0]\nC()", ""),
            ("d={Mut:1}\nk=d.keys\nC=next(k().__iter__())\nC()", ""),
            ("fk=dict.fromkeys\nviews=[fk]\nC,=views[0]([Mut])\nC()", ""),
        )
    )
    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    for call in (
        "dict(e=n.install)['e'](evil)",
        'match n:\n        case x if getattr(x,"install"):\n            x.install(evil)',
        "f=n.install\n    f(*(evil,))",
        "f=n.install\n    f(**{'fn': evil})",
        "(lambda: n.install)()(evil)",
        "fns={0:n.install}\n    for _,f in fns.items():\n        f(evil)",
    ):
        routes = f"""
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {call}
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        files = {
            "app/helpers.py": _helpers_source(),
            "app/pkg/__init__.py": "",
            "app/pkg/nested.py": nested,
            "app/routes.py": routes.strip(),
        }
        findings = analyze_bypass_authority_unit(
            files,
            entry_path="app/routes.py",
            function_name="handler",
            bypass_fields=frozenset({"bypass_filter"}),
            scope_proof=_scope(*files, import_roots=("app",)),
        )
        assert findings[0].status != "authorized", call
        assert findings[0].reason != "source_proved_server_authority_write", call


def test_twelfth_pass_positive_authorized_smoke() -> None:
    """Benign analogues of the twelfth-pass shapes remain authorized."""

    for body in (
        "d={}\ne=copy.copy(d)\ne|={}\nlen(e)",
        "sorted([int], key=type.__call__)",
        "xs=[1]\nxs.sort(key=lambda x: x)",
        'ns=types.__dict__\nkeys=["MappingProxyType"]\nk=keys[0]\n'
        'Proxy=getattr(ns,"get")(k)\nProxy({})',
        "import itertools\nlist(itertools.chain.from_iterable([[1]]))",
        "xs=[]\nlist.__iadd__(xs, [1])\nxs[0]",
        "mk=int\nmk(0)",
    ):
        src = (
            "import helpers\nimport copy\nimport types\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status == "authorized", body
        assert findings[0].reason == "source_proved_server_authority_write", body


def test_thirteenth_pass_identity_getattr_import_key_never_authorized() -> None:
    """getattr/import-as/reduce-as/star-lambda/list.sort key= peels."""

    _assert_ninth_not_authorized(
        (
            (
                'import builtins\n'
                'getattr(builtins,"sorted")([Mut], key=type.__call__)',
                "import builtins",
            ),
            (
                'import builtins\n'
                'getattr(builtins,"max")([Mut], key=type.__call__)',
                "import builtins",
            ),
            (
                'import builtins\n'
                'getattr(builtins,"min")([Mut], key=type.__call__)',
                "import builtins",
            ),
            (
                "from builtins import sorted as s\ns([Mut], key=type.__call__)",
                "from builtins import sorted as s",
            ),
            (
                "from functools import reduce as rd\n"
                "rd(lambda a,f: f(Mut) or a, [type.__call__], 0)",
                "from functools import reduce as rd",
            ),
            ("(lambda *a: a[0](Mut))(*[type.__call__])", ""),
            ("xs=[Mut]\nlist.sort(xs, key=type.__call__)", ""),
            ("xs=[Mut]\ng=list.sort\ng(xs, key=type.__call__)", ""),
        )
    )


def test_thirteenth_pass_cf_getattr_maps_ns_for_iter_never_authorized() -> None:
    """getattr ChainMap maps, vars/setitem/AnnAssign NS, For/Match iadd."""

    ex = _NINTH_EXEC
    imp = (
        "from collections import ChainMap\n"
        "import operator, types"
    )
    plain = (
        f'cm=ChainMap()\ngetattr(cm,"maps").append({{"e":exec}})\ncm["e"]({ex})',
        f'cm=ChainMap()\ngetattr(cm.maps,"append")({{"e":exec}})\ncm["e"]({ex})',
        f'cm=ChainMap()\ngetattr(cm.maps,"extend")([{{"e":exec}}])\ncm["e"]({ex})',
        f'cm=ChainMap()\ngetattr(cm.maps,"insert")(0, {{"e":exec}})\ncm["e"]({ex})',
        f'cm=ChainMap()\ngetattr(cm.maps,"__iadd__")([{{"e":exec}}])\ncm["e"]({ex})',
        f'ns=types.SimpleNamespace()\nvars(ns)["e"]=exec\nns.e({ex})',
        f'ns=types.SimpleNamespace()\n'
        f'operator.setitem(ns.__dict__,"e",exec)\nns.e({ex})',
        f'ns=types.SimpleNamespace()\n'
        f'operator.setitem(vars(ns),"e",exec)\nns.e({ex})',
        f"ns=types.SimpleNamespace()\nns.e: object = exec\nns.e({ex})",
        f"xs=[]\nfor f in operator.iadd(xs,[exec]):\n    f({ex})",
        f"xs=[]\nfor f in operator.iconcat(xs,[exec]):\n    f({ex})",
        f"xs=[]\nfor f in xs.__iadd__([exec]):\n    f({ex})",
        f"xs=[]\nmatch operator.iadd(xs,[exec]):\n    case [f]:\n        f({ex})",
        f"xs=[]\nmatch operator.iconcat(xs,[exec]):\n    case [f]:\n        f({ex})",
    )
    _assert_ninth_not_authorized(tuple((c, imp) for c in plain))


def test_thirteenth_pass_alias_key_peel_never_authorized() -> None:
    """.get/__getitem__/getitem/Name-index/itemgetter/pop/nested/getattr."""

    alias_imports = "import types"
    cases = (
        'ns=types.__dict__\n'
        'keys={"x":"MappingProxyType"}\n'
        'k=keys.get("x")\n'
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys=["MappingProxyType"]\n'
        "k=keys.__getitem__(0)\n"
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys={"x":"MappingProxyType"}\n'
        'k=keys.__getitem__("x")\n'
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys=["MappingProxyType"]\n'
        "import operator\n"
        "k=operator.getitem(keys,0)\n"
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys=["MappingProxyType"]\n'
        "idx=0\n"
        "k=keys[idx]\n"
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys={"x":"MappingProxyType"}\n'
        'xk="x"\n'
        "k=keys[xk]\n"
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys={"x":"MappingProxyType"}\n'
        "import operator\n"
        'k=operator.itemgetter("x")(keys)\n'
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys=[["MappingProxyType"]]\n'
        "k=keys[0][0]\n"
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys={"x":"MappingProxyType"}\n'
        'k=keys.pop("x")\n'
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys={"x":"MappingProxyType"}\n'
        'k=getattr(keys,"get")("x")\n'
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys=["MappingProxyType"]\n'
        'k=getattr(keys,"__getitem__")(0)\n'
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
    )
    for body in cases:
        src = (
            "import helpers\n"
            f"{alias_imports}\n"
            "def evil(state, value):\n"
            "    state.bypass_filter = value\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_thirteenth_pass_lexical_copy_peels_never_authorized() -> None:
    """import-as/module alias/dict.copy/packed/deepcopy/methodcaller peels."""

    _assert_ninth_not_authorized(
        (
            (
                "import copy as cp\nd={Mut:1}\ne=cp.copy(d)\ne|={}\nC,=e.keys()\nC()",
                "import copy as cp",
            ),
            (
                "import copy\nm=copy\nd={Mut:1}\ne=m.copy(d)\ne|={}\nC,=e.keys()\nC()",
                "import copy",
            ),
            ("d={Mut:1}\ne=dict.copy(d)\ne|={}\nC,=e.keys()\nC()", ""),
            (
                'd={Mut:1}\ne=getattr(dict,"copy")(d)\ne|={}\nC,=e.keys()\nC()',
                "",
            ),
            (
                "import copy\nd={Mut:1}\ne=[copy.copy][0](d)\ne|={}\nC,=e.keys()\nC()",
                "import copy",
            ),
            (
                "import copy\nd={Mut:1}\ne=next(iter([copy.copy]))(d)\ne|={}\n"
                "C,=e.keys()\nC()",
                "import copy",
            ),
            (
                "import copy\nd={Mut:1}\ne={0:copy.copy}[0](d)\ne|={}\nC,=e.keys()\nC()",
                "import copy",
            ),
            (
                "import copy\nd={Mut:1}\ne=[copy.deepcopy][0](d)\ne|={}\n"
                "C,=e.keys()\nC()",
                "import copy",
            ),
            (
                "import copy\nfrom operator import methodcaller\n"
                "d={Mut:1}\ne=methodcaller('copy')(d)\ne|={}\nC,=e.keys()\nC()",
                "import copy\nfrom operator import methodcaller",
            ),
            (
                "import copy\nfrom operator import methodcaller\n"
                "d={Mut:1}\ne=copy.copy(d)\ne|={}\n"
                "C,=methodcaller('keys')(e)\nC()",
                "import copy\nfrom operator import methodcaller",
            ),
            (
                "import copy\nfrom operator import methodcaller\n"
                'd={"c":Mut}\ne=copy.copy(d)\ne|={}\n'
                "C,=methodcaller('values')(e)\nC()",
                "import copy\nfrom operator import methodcaller",
            ),
            (
                "import copy\nfrom operator import methodcaller\n"
                'd={"c":Mut}\ne=copy.copy(d)\ne|={}\n'
                "k,C=methodcaller('popitem')(e)\nC()",
                "import copy\nfrom operator import methodcaller",
            ),
        )
    )


def test_thirteenth_pass_class_func_ns_never_authorized() -> None:
    """Name-bound __func__ / __func__.__call__ / bare/Name/setattr/match NS."""

    cases = (
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
mk=Mut.make
mk.__func__(Mut)
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
Mut.make.__func__.__call__(Mut)
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @staticmethod
    def smake():
        helpers.write_state = evil
mk=Mut.smake
mk.__func__()
""".strip(),
        """
import types
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
types.SimpleNamespace(m=Mut.make).m()
""".strip(),
        """
import types
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
ns=types.SimpleNamespace(m=Mut.make)
ns.m()
""".strip(),
        """
import types
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
ns=types.SimpleNamespace()
setattr(ns,"m",Mut.make)
ns.m()
""".strip(),
        """
import types
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
ns=types.SimpleNamespace(m=Mut.make)
match ns:
    case types.SimpleNamespace(m=mk):
        mk()
""".strip(),
        """
import types
class Mut:
    def __init__(self):
        helpers.write_state = evil
    def poke(self):
        helpers.write_state = evil
m=Mut.__new__(Mut)
types.SimpleNamespace(p=m.poke).p()
""".strip(),
    )
    for body in cases:
        src = (
            "import helpers\n"
            "def evil(state, value):\n"
            "    state.bypass_filter = value\n"
            "def handler(request, bypass_filter=False):\n"
            + "\n".join(f"    {ln}" if ln else ln for ln in body.split("\n"))
            + "\n    helpers.write_state(request.state, bypass_filter)\n"
            "    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_thirteenth_pass_interproc_pack_depth_never_authorized() -> None:
    """Nested/dict()/star/|/copy/ChainMap/MPT/__iter__/fromkeys + install."""

    _assert_ninth_not_authorized(
        (
            (
                "d={Mut:1}\nviews={'outer':{'v':d.keys}}\n"
                "for C in views['outer']['v']():\n    C()",
                "",
            ),
            (
                "d={Mut:1}\nviews=dict(v=d.keys)\nfor C in views['v']():\n    C()",
                "",
            ),
            (
                "d={Mut:1}\nviews=dict(**{'v':d.keys})\n"
                "for C in views['v']():\n    C()",
                "",
            ),
            (
                "d={Mut:1}\nviews={}|{'v':d.keys}\nfor C in views['v']():\n    C()",
                "",
            ),
            ("d={Mut:1}\nviews=[[d.keys]]\nC,=views[0][0]()\nC()", ""),
            (
                "d={Mut:1}\nviews=[{'v':d.keys}]\nC,=views[0]['v']()\nC()",
                "",
            ),
            ("d={Mut:1}\nk=d.__iter__\nC=next(k())\nC()", ""),
            ("d={Mut:1}\nk=getattr(d,'__iter__')\nC=next(k())\nC()", ""),
            (
                "fk=getattr(dict,'fromkeys')\nviews=[fk]\nC,=views[0]([Mut])\nC()",
                "",
            ),
            (
                "from collections import ChainMap\n"
                "d={Mut:1}\nviews=ChainMap({'v':d.keys})\n"
                "for C in views['v']():\n    C()",
                "from collections import ChainMap",
            ),
            (
                "import copy\nd={Mut:1}\nviews=copy.copy({'v':d.keys})\n"
                "for C in views['v']():\n    C()",
                "import copy",
            ),
            (
                "import types\nd={Mut:1}\n"
                "views=types.MappingProxyType({'v':d.keys})\n"
                "for C in views['v']():\n    C()",
                "import types",
            ),
        )
    )
    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    for call in (
        "d=dict(); d.update({'e':n.install}); d['e'](evil)",
        "d=dict(list({'e':n.install}.items())); d['e'](evil)",
        "d=dict(); it=iter({'e':n.install}.items()); "
        "d.update([next(it)]); d['e'](evil)",
        "(lambda: getattr(n,'install'))()(evil)",
        "packs={'outer':{'e':n.install}}; packs['outer']['e'](evil)",
        "import types; types.SimpleNamespace(e=n.install).e(evil)",
        "d=dict(); d|={'e':n.install}; d['e'](evil)",
        "(lambda *a: a[0](evil))(*[n.install])",
        "import copy; copy.copy([n.install])[0](evil)",
    ):
        routes = f"""
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {call}
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        files = {
            "app/helpers.py": _helpers_source(),
            "app/pkg/__init__.py": "",
            "app/pkg/nested.py": nested,
            "app/routes.py": routes.strip(),
        }
        findings = analyze_bypass_authority_unit(
            files,
            entry_path="app/routes.py",
            function_name="handler",
            bypass_fields=frozenset({"bypass_filter"}),
            scope_proof=_scope(*files, import_roots=("app",)),
        )
        assert findings[0].status != "authorized", call
        assert findings[0].reason != "source_proved_server_authority_write", call


def test_thirteenth_pass_positive_authorized_smoke() -> None:
    """Benign analogues of the thirteenth-pass shapes remain authorized."""

    for body in (
        'import builtins\ngattrattr=getattr\n'
        'getattr(builtins,"sorted")([1], key=lambda x: x)',
        "from builtins import sorted as s\ns([1], key=lambda x: x)",
        "xs=[1]\nlist.sort(xs, key=lambda x: x)",
        "import copy as cp\nd={}\ne=cp.copy(d)\ne|={}\nlen(e)",
        "d={}\ne=dict.copy(d)\ne|={}\nlen(e)",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'k=keys.get("x")\nProxy=getattr(ns,"get")(k)\nProxy({})',
        "from collections import ChainMap\n"
        'cm=ChainMap()\ngetattr(cm,"maps").append({})\nlen(cm)',
        "mk=int\nmk(0)",
    ):
        src = (
            "import helpers\nimport copy\nimport types\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status == "authorized", body
        assert findings[0].reason == "source_proved_server_authority_write", body


def test_fourteenth_pass_lexical_packed_methodcaller_partial_never_authorized() -> None:
    """Call-in-pack methodcaller/partial copy and view peels."""

    _assert_ninth_not_authorized(
        (
            (
                "from operator import methodcaller\n"
                "d={Mut:1}\ne=[methodcaller('copy')][0](d)\ne|={}\nC,=e.keys()\nC()",
                "from operator import methodcaller",
            ),
            (
                "from operator import methodcaller\n"
                "d={Mut:1}\ne=next(iter([methodcaller('copy')]))(d)\ne|={}\n"
                "C,=e.keys()\nC()",
                "from operator import methodcaller",
            ),
            (
                "from operator import methodcaller\n"
                "d={Mut:1}\ne={0:methodcaller('copy')}[0](d)\ne|={}\n"
                "C,=e.keys()\nC()",
                "from operator import methodcaller",
            ),
            (
                "import operator\n"
                "d={Mut:1}\ne=[operator.methodcaller('copy')][0](d)\ne|={}\n"
                "C,=e.keys()\nC()",
                "import operator",
            ),
            (
                "import copy\nfrom operator import methodcaller\n"
                "d={Mut:1}\ne=copy.copy(d)\ne|={}\n"
                "C,=[methodcaller('keys')][0](e)\nC()",
                "import copy\nfrom operator import methodcaller",
            ),
            (
                "import copy\nfrom operator import methodcaller\n"
                'd={"c":Mut}\ne=copy.copy(d)\ne|={}\n'
                "C,=[methodcaller('values')][0](e)\nC()",
                "import copy\nfrom operator import methodcaller",
            ),
            (
                "import copy\nfrom operator import methodcaller\n"
                'd={"c":Mut}\ne=copy.copy(d)\ne|={}\n'
                "k,C=[methodcaller('popitem')][0](e)\nC()",
                "import copy\nfrom operator import methodcaller",
            ),
            (
                "from functools import partial\nimport copy\n"
                "d={Mut:1}\ne=[partial(copy.copy)][0](d)\ne|={}\n"
                "C,=e.keys()\nC()",
                "from functools import partial\nimport copy",
            ),
            (
                "from functools import partial\nimport copy\n"
                "d={Mut:1}\ne=next(iter([partial(copy.copy)]))(d)\ne|={}\n"
                "C,=e.keys()\nC()",
                "from functools import partial\nimport copy",
            ),
        )
    )


def test_fourteenth_pass_identity_key_applicator_packs_never_authorized() -> None:
    """Packed/BoolOp/IfExp/__call__/bound-sort key= applicator peels."""

    _assert_ninth_not_authorized(
        (
            (
                'import builtins\n'
                '[getattr(builtins,"sorted")][0]([Mut], key=type.__call__)',
                "import builtins",
            ),
            (
                'import builtins\n'
                '(False or getattr(builtins,"max"))([Mut], key=type.__call__)',
                "import builtins",
            ),
            (
                'import builtins\n'
                '(getattr(builtins,"min") if True else len)'
                "([Mut], key=type.__call__)",
                "import builtins",
            ),
            (
                'import builtins\n'
                '{0:getattr(builtins,"sorted")}[0]([Mut], key=type.__call__)',
                "import builtins",
            ),
            (
                'import builtins\n'
                'next(iter([getattr(builtins,"sorted")]))'
                "([Mut], key=type.__call__)",
                "import builtins",
            ),
            (
                "from builtins import sorted as s\n"
                "s.__call__([Mut], key=type.__call__)",
                "from builtins import sorted as s",
            ),
            (
                "from builtins import max as mx\n"
                "mx.__call__([Mut], key=type.__call__)",
                "from builtins import max as mx",
            ),
            (
                "from builtins import sorted as s\n"
                "[s][0]([Mut], key=type.__call__)",
                "from builtins import sorted as s",
            ),
            (
                "from builtins import sorted as s\n"
                "(False or s)([Mut], key=type.__call__)",
                "from builtins import sorted as s",
            ),
            (
                "from functools import reduce as rd\n"
                "[rd][0](lambda a,f: f(Mut) or a, [type.__call__], 0)",
                "from functools import reduce as rd",
            ),
            (
                'import functools\n'
                '[getattr(functools,"reduce")][0]'
                "(lambda a,f: f(Mut) or a, [type.__call__], 0)",
                "import functools",
            ),
            (
                'xs=[Mut]\ngattrattr=getattr\n'
                'getattr(list,"sort")(xs, key=type.__call__)',
                "",
            ),
            ("xs=[Mut]\n[list.sort][0](xs, key=type.__call__)", ""),
            (
                "xs=[Mut]\n(list.sort if True else len)(xs, key=type.__call__)",
                "",
            ),
            ("xs=[Mut]\n(False or list.sort)(xs, key=type.__call__)", ""),
            ("xs=[Mut]\ng=xs.sort\ng(key=type.__call__)", ""),
        )
    )


def test_fourteenth_pass_cf_maps_vars_boolop_iadd_never_authorized() -> None:
    """ChainMap Name/unbound maps, vars update, BoolOp/IfExp iadd."""

    ex = _NINTH_EXEC
    imp = "from collections import ChainMap\nimport operator, types"
    cases = (
        f'cm=ChainMap()\nlist.append(getattr(cm,"maps"), {{"e":exec}})\n'
        f'cm["e"]({ex})',
        f'cm=ChainMap()\nlist.extend(getattr(cm,"maps"), [{{"e":exec}}])\n'
        f'cm["e"]({ex})',
        f'cm=ChainMap()\nm=cm.maps\nm.append({{"e":exec}})\ncm["e"]({ex})',
        f'cm=ChainMap()\n'
        f'object.__getattribute__(cm,"maps").append({{"e":exec}})\n'
        f'cm["e"]({ex})',
        f'cm=ChainMap()\nfrom operator import methodcaller\n'
        f'methodcaller("append", {{"e":exec}})(getattr(cm,"maps"))\n'
        f'cm["e"]({ex})',
        f'ns=types.SimpleNamespace()\nvars(ns).update({{"e":exec}})\n'
        f"ns.e({ex})",
        f'ns=types.SimpleNamespace()\nvars(ns).setdefault("e",exec)\n'
        f"ns.e({ex})",
        f'ns=types.SimpleNamespace()\n'
        f'ns.__dict__.__setitem__("e",exec)\nns.e({ex})',
        f'ns=types.SimpleNamespace()\nd=vars(ns)\nd["e"]=exec\nns.e({ex})',
        f"xs=[]\nfor f in (True and operator.iadd(xs,[exec])):\n    f({ex})",
        f"xs=[]\nfor f in (operator.iadd(xs,[exec]) if True else xs):\n"
        f"    f({ex})",
        f"xs=[]\nmatch (True and operator.iadd(xs,[exec])):\n"
        f"    case [f]:\n        f({ex})",
        f"xs=[]\nmatch (operator.iconcat(xs,[exec]) if True else xs):\n"
        f"    case [f]:\n        f({ex})",
    )
    _assert_ninth_not_authorized(tuple((c, imp) for c in cases))
    _assert_ninth_not_authorized(
        (
            (
                'ns=types.SimpleNamespace()\nvars(ns)["m"]=Mut\nns.m()',
                "import types",
            ),
        )
    )


def test_fourteenth_pass_alias_name_nested_mutate_never_authorized() -> None:
    """Name-bound itemgetter, nested chains, mutate-then-project peels."""

    alias_imports = "import types, operator"
    cases = (
        'ns=types.__dict__\n'
        'keys={"x":"MappingProxyType"}\n'
        'ig=operator.itemgetter("x")\n'
        "k=ig(keys)\n"
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys={"x":{"y":"MappingProxyType"}}\n'
        'k=operator.getitem(operator.getitem(keys,"x"),"y")\n'
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys={"x":{"y":"MappingProxyType"}}\n'
        'k=operator.itemgetter("y")(operator.itemgetter("x")(keys))\n'
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys={"x":{"y":"MappingProxyType"}}\n'
        'k=keys.get("x").get("y")\n'
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys={"x":"MappingProxyType"}\n'
        'keys["z"]=keys.pop("x")\n'
        'k=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\n'
        'keys={"x":"MappingProxyType"}\n'
        'keys["z"]=keys["x"]\n'
        'del keys["x"]\n'
        'k=keys.__getitem__("z")\n'
        'Proxy=getattr(ns,"get")(k)\n'
        's=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
    )
    for body in cases:
        src = (
            "import helpers\n"
            f"{alias_imports}\n"
            "def evil(state, value):\n"
            "    state.bypass_filter = value\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_fourteenth_pass_class_func_sn_packs_never_authorized() -> None:
    """getattr/packed __func__ and SN IfExp/BoolOp/copy/builtins.setattr."""

    cases = (
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
mk=Mut.make
getattr(mk,"__func__")(Mut)
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
mk=Mut.make
[mk][0].__func__(Mut)
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
mk=Mut.make
next(iter([mk])).__func__(Mut)
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
getattr(Mut,"make").__func__(Mut)
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
(types.SimpleNamespace(m=Mut.make) if True else None).m()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
(False or types.SimpleNamespace(m=Mut.make)).m()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
[types.SimpleNamespace(m=Mut.make)][0].m()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
import copy
ns=types.SimpleNamespace(m=Mut.make)
copy.copy(ns).m()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
import copy
ns=types.SimpleNamespace(m=Mut.make)
copy.deepcopy(ns).m()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
types.SimpleNamespace(**dict(m=Mut.make)).m()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
    @classmethod
    def make(cls):
        return cls()
import builtins
ns=types.SimpleNamespace()
builtins.setattr(ns,"m",Mut.make)
ns.m()
""".strip(),
        """
class Mut:
    def __init__(self):
        helpers.write_state = evil
ns=types.SimpleNamespace()
vars(ns)["m"]=Mut
ns.m()
""".strip(),
    )
    for body in cases:
        findings = _unit(_ninth_src(body, imports="import types\nimport copy\nimport builtins"))
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_fourteenth_pass_interproc_list_carrier_ior_never_authorized() -> None:
    """List-carrier copy/deepcopy/list and install __ior__/items peels."""

    _assert_ninth_not_authorized(
        (
            (
                "import copy\nd={Mut:1}\nviews=copy.copy([{'v':d.keys}])\n"
                "C,=views[0]['v']()\nC()",
                "import copy",
            ),
            (
                "import copy\nd={Mut:1}\nviews=copy.deepcopy([{'v':d.keys}])\n"
                "C,=views[0]['v']()\nC()",
                "import copy",
            ),
            (
                "import copy as cp\nd={Mut:1}\nviews=cp.copy([{'v':d.keys}])\n"
                "C,=views[0]['v']()\nC()",
                "import copy as cp",
            ),
            (
                "d={Mut:1}\nviews=[{'v':d.keys}].copy()\n"
                "C,=views[0]['v']()\nC()",
                "",
            ),
            (
                "d={Mut:1}\nviews=list([{'v':d.keys}])\n"
                "C,=views[0]['v']()\nC()",
                "",
            ),
            (
                "import copy\nd={Mut:1}\nviews=copy.copy([[d.keys]])\n"
                "C,=views[0][0]()\nC()",
                "import copy",
            ),
        )
    )
    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    for call in (
        "import copy; copy.deepcopy([n.install])[0](evil)",
        "d=dict(); d.__ior__({'e':n.install}); d['e'](evil)",
        "import operator; d=dict(); operator.ior(d, {'e':n.install}); "
        "d['e'](evil)",
        "d=dict(); getattr(d,'__ior__')({'e':n.install}); d['e'](evil)",
        "fns={'e':n.install}; list(fns.items())[0][1](evil)",
        "fns={'e':n.install}; tuple(fns.items())[0][1](evil)",
        "fns={'e':n.install}; [*fns.items()][0][1](evil)",
        "fns={'e':n.install}; next(iter(fns.items()))[1](evil)",
        "import copy; copy.copy({'outer':[n.install]})['outer'][0](evil)",
        "import copy; (lambda xs: xs[0](evil))(copy.copy([n.install]))",
        "list([{'e':n.install}])[0]['e'](evil)",
    ):
        routes = f"""
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {call}
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        files = {
            "app/helpers.py": _helpers_source(),
            "app/pkg/__init__.py": "",
            "app/pkg/nested.py": nested,
            "app/routes.py": routes.strip(),
        }
        findings = analyze_bypass_authority_unit(
            files,
            entry_path="app/routes.py",
            function_name="handler",
            bypass_fields=frozenset({"bypass_filter"}),
            scope_proof=_scope(*files, import_roots=("app",)),
        )
        assert findings[0].status != "authorized", call
        assert findings[0].reason != "source_proved_server_authority_write", call


def test_fourteenth_pass_positive_authorized_smoke() -> None:
    """Benign analogues of the fourteenth-pass shapes remain authorized."""

    for body in (
        "from operator import methodcaller\nd={}\n"
        "e=[methodcaller('copy')][0](d)\ne|={}\nlen(e)",
        "from functools import partial\nimport copy\nd={}\n"
        "e=[partial(copy.copy)][0](d)\ne|={}\nlen(e)",
        'import builtins\n'
        '[getattr(builtins,"sorted")][0]([1], key=lambda x: x)',
        "from builtins import sorted as s\ns.__call__([1], key=lambda x: x)",
        "xs=[1]\ng=xs.sort\ng(key=lambda x: x)",
        "import copy\nd={}\nviews=copy.copy([{'v':d.keys}])\nlen(views)",
        "from collections import ChainMap\n"
        'cm=ChainMap()\nlist.append(getattr(cm,"maps"), {})\nlen(cm)',
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'ig=operator.itemgetter("x")\nk=ig(keys)\n'
        'Proxy=getattr(ns,"get")(k)\nProxy({})',
    ):
        src = (
            "import helpers\nimport copy\nimport types\nimport operator\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status == "authorized", body
        assert findings[0].reason == "source_proved_server_authority_write", body


def test_fifteenth_pass_alias_mid_name_and_mutate_never_authorized() -> None:
    """Mid-Name get/itemgetter + setitem/update/|=/methodcaller get peels."""

    cases = (
        'ns=types.__dict__\nkeys={"x":{"y":"MappingProxyType"}}\n'
        'mid=keys.get("x")\nk=mid.get("y")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":{"y":"MappingProxyType"}}\n'
        'mid=operator.itemgetter("x")(keys)\nk=operator.itemgetter("y")(mid)\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'operator.setitem(keys,"z",keys.pop("x"))\nk=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'keys.__setitem__("z",keys.pop("x"))\nk=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'keys.update(z=keys.pop("x"))\nk=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'keys |= {"z": keys.pop("x")}\nk=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'k=getattr(operator,"itemgetter")("x")(keys)\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":{"y":"MappingProxyType"}}\n'
        'mid=operator.methodcaller("get","x")(keys)\n'
        'k=operator.methodcaller("get","y")(mid)\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'c=keys\nc["z"]=c.pop("x")\nk=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
    )
    for body in cases:
        findings = _unit(
            "import helpers\nimport types, operator\n"
            "def evil(state, value):\n"
            "    state.bypass_filter = value\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_fifteenth_pass_lexical_getattr_partial_never_authorized() -> None:
    """getattr(methodcaller)/partial(copy)/partial(getattr(copy)) packs."""

    _assert_ninth_not_authorized(
        (
            (
                "import operator\nd={Mut:1}\n"
                "e=[getattr(operator,'methodcaller')('copy')][0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                "import operator",
            ),
            (
                "from functools import partial\nimport copy\nd={Mut:1}\n"
                "e=[partial(copy.copy,d)][0]()\ne|={}\nC,=e.keys()\nC()",
                "from functools import partial\nimport copy",
            ),
            (
                "from functools import partial\nimport copy\nd={Mut:1}\n"
                "e=[partial(getattr(copy,'copy'))][0](d)\ne|={}\nC,=e.keys()\nC()",
                "from functools import partial\nimport copy",
            ),
        )
    )


def test_fifteenth_pass_class_setattr_sn_vars_never_authorized() -> None:
    """setattr import-as/getattr/packed, SN list/next, vars setdefault/setitem."""

    mut = (
        "class Mut:\n"
        "    def __init__(self):\n"
        "        helpers.write_state = evil\n"
        "    @classmethod\n"
        "    def make(cls):\n"
        "        return cls()\n"
    )
    cases = (
        mut
        + 'ns=types.SimpleNamespace()\nsa(ns,"m",Mut.make)\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\ngattrattr=getattr\n'
        'gattrattr(builtins,"setattr")(ns,"m",Mut.make)\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\n'
        '[getattr(builtins,"setattr")][0](ns,"m",Mut.make)\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\nvars(ns).setdefault("m",Mut.make)\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\nvars(ns).__setitem__("m",Mut.make)\nns.m()',
        mut + "SN=types.SimpleNamespace\n[SN][0](m=Mut.make).m()",
        mut + "next(iter([types.SimpleNamespace(m=Mut.make)])).m()",
        f'(types.SimpleNamespace(e=exec) if True else None).e({_NINTH_EXEC})',
        f'(types.SimpleNamespace(e=exec) or None).e({_NINTH_EXEC})',
        f'[types.SimpleNamespace(e=exec)][0].e({_NINTH_EXEC})',
        f'import copy\ncopy.copy(types.SimpleNamespace(e=exec)).e({_NINTH_EXEC})',
    )
    for body in cases:
        findings = _unit(
            _ninth_src(
                body,
                imports=(
                    "import types\nimport builtins\nimport copy\n"
                    "from builtins import setattr as sa"
                ),
            )
        )
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_fifteenth_pass_cf_packed_append_attrgetter_ior_never_authorized() -> None:
    """Packed list.append, attrgetter(maps), methodcaller/vars ior peels."""

    ex = _NINTH_EXEC
    imp = (
        "from collections import ChainMap\nimport operator, types\n"
        "from operator import methodcaller, attrgetter\n"
        "from builtins import list as L"
    )
    _assert_ninth_not_authorized(
        tuple(
            (c, imp)
            for c in (
                f'cm=ChainMap()\n[list.append][0](getattr(cm,"maps"), {{"e":exec}})\n'
                f'cm["e"]({ex})',
                f'cm=ChainMap()\n(0 or list.append)(getattr(cm,"maps"), {{"e":exec}})\n'
                f'cm["e"]({ex})',
                f'cm=ChainMap()\nL.append(getattr(cm,"maps"), {{"e":exec}})\n'
                f'cm["e"]({ex})',
                f'cm=ChainMap()\nattrgetter("maps")(cm).append({{"e":exec}})\n'
                f'cm["e"]({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'methodcaller("update", {{"e":exec}})(vars(ns))\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'methodcaller("setdefault", "e", exec)(vars(ns))\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'operator.ior(vars(ns), {{"e":exec}})\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'dict.__ior__(vars(ns), {{"e":exec}})\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'ns.__dict__.__ior__({{"e":exec}})\nns.e({ex})',
            )
        )
    )


def test_fifteenth_pass_interproc_copy_slice_values_never_authorized() -> None:
    """Name-carrier copy/from-import/slice/pop/values/fn/packed deepcopy."""

    _assert_ninth_not_authorized(
        (
            (
                "import copy\nd={Mut:1}\ncarrier=[{'v':d.keys}]\n"
                "views=copy.copy(carrier)\nC,=views[0]['v']()\nC()",
                "import copy",
            ),
            (
                "from copy import copy as c\nd={Mut:1}\n"
                "views=c([{'v':d.keys}])\nC,=views[0]['v']()\nC()",
                "from copy import copy as c",
            ),
            (
                "from copy import deepcopy as dc\nd={Mut:1}\n"
                "views=dc([{'v':d.keys}])\nC,=views[0]['v']()\nC()",
                "from copy import deepcopy as dc",
            ),
            (
                "import copy\nd={Mut:1}\n"
                "views=copy.copy([{'v':d.keys}])[:]\nC,=views[0]['v']()\nC()",
                "import copy",
            ),
            (
                "import copy\nd={Mut:1}\ntmp=copy.copy([{'v':d.keys}])\n"
                "views=tmp[:]\nC,=views[0]['v']()\nC()",
                "import copy",
            ),
            (
                "import copy\nd={Mut:1}\nviews=copy.copy([{'v':d.keys}])\n"
                "C,=views.pop()['v']()\nC()",
                "import copy",
            ),
            (
                'import copy\nd={"c":Mut}\nviews=copy.copy([d])\n'
                "C,=list(views[0].values())[0]\nC()",
                "import copy",
            ),
            (
                "import copy\nd={Mut:1}\nfn=copy.copy\n"
                "views=fn([{'v':d.keys}])\nC,=views[0]['v']()\nC()",
                "import copy",
            ),
            (
                "import copy\nd={Mut:1}\n"
                "views=[copy.copy][0]([{'v':d.keys}])\nC,=views[0]['v']()\nC()",
                "import copy",
            ),
            ("import copy\n[copy.deepcopy][0]([Mut])[0]()", "import copy"),
        )
    )
    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    for call in (
        "from operator import methodcaller; d=dict(); "
        "methodcaller('__ior__', {'e':n.install})(d); d['e'](evil)",
        "fns={'e':n.install}; [x for x in fns.items()][0][1](evil)",
        "import copy; [copy.deepcopy][0]([n.install])[0](evil)",
    ):
        routes = f"""
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {call}
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        files = {
            "app/helpers.py": _helpers_source(),
            "app/pkg/__init__.py": "",
            "app/pkg/nested.py": nested,
            "app/routes.py": routes.strip(),
        }
        findings = analyze_bypass_authority_unit(
            files,
            entry_path="app/routes.py",
            function_name="handler",
            bypass_fields=frozenset({"bypass_filter"}),
            scope_proof=_scope(*files, import_roots=("app",)),
        )
        assert findings[0].status != "authorized", call
        assert findings[0].reason != "source_proved_server_authority_write", call


def test_fifteenth_pass_identity_call_sort_packs_never_authorized() -> None:
    """sorted/list.sort __call__ packs, methodcaller sort, list-as-L peels."""

    _assert_ninth_not_authorized(
        (
            (
                'import builtins\ngattrattr=getattr\n'
                'gattrattr(builtins,"sorted").__call__([Mut], key=type.__call__)',
                "import builtins",
            ),
            (
                "import builtins\nbuiltins.sorted.__call__([Mut], key=type.__call__)",
                "import builtins",
            ),
            (
                'import builtins\ngattrattr=getattr\n'
                'g=gattrattr(builtins,"sorted").__call__\n'
                "g([Mut], key=type.__call__)",
                "import builtins",
            ),
            (
                "from builtins import sorted as s\n"
                "s.__call__.__call__([Mut], key=type.__call__)",
                "from builtins import sorted as s",
            ),
            (
                "xs=[Mut]\nlist.sort.__call__(xs, key=type.__call__)",
                "",
            ),
            (
                "xs=[Mut]\n[getattr(xs,'sort')][0](key=type.__call__)",
                "",
            ),
            (
                "xs=[Mut]\n(0 or getattr(xs,'sort'))(key=type.__call__)",
                "",
            ),
            (
                "from operator import methodcaller\nxs=[Mut]\n"
                "methodcaller('sort', key=type.__call__)(xs)",
                "from operator import methodcaller",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "L.sort(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "[L.sort][0](xs, key=type.__call__)",
                "from builtins import list as L",
            ),
        )
    )


def test_fifteenth_pass_positive_authorized_smoke() -> None:
    """Benign analogues of fifteenth-pass shapes remain authorized."""

    for body in (
        "from functools import partial\nimport copy\nd={}\n"
        "e=[partial(copy.copy,d)][0]()\ne|={}\nlen(e)",
        'import builtins\ngattrattr=getattr\n'
        'gattrattr(builtins,"sorted")([1], key=lambda x: x)',
        "from builtins import list as L\nxs=[1]\nL.sort(xs, key=lambda x: x)",
        "import copy\nd={}\nfn=copy.copy\nviews=fn([{'v':d.keys}])\nlen(views)",
        "import copy\nd={}\nviews=copy.copy([{'v':d.keys}])[:]\nlen(views)",
        "from collections import ChainMap\nfrom builtins import list as L\n"
        'cm=ChainMap()\nL.append(getattr(cm,"maps"), {})\nlen(cm)',
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'keys.update({"z": keys.pop("x")})\nk=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\nProxy({})',
        "import types\nns=types.SimpleNamespace()\n"
        'from builtins import setattr as sa\nsa(ns,"x",1)\nns.x',
    ):
        src = (
            "import helpers\nimport copy\nimport types\nimport operator\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status == "authorized", body
        assert findings[0].reason == "source_proved_server_authority_write", body


def test_sixteenth_pass_lexical_slice_pack_never_authorized() -> None:
    """Slice-then-index packing of getattr/methodcaller/partial copy peels."""

    _assert_ninth_not_authorized(
        (
            (
                "import operator\nd={Mut:1}\n"
                "e=[getattr(operator,'methodcaller')('copy')][:1][0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                "import operator",
            ),
            (
                "import operator\nd={Mut:1}\n"
                "e=[getattr(operator,'methodcaller')('copy')][0:1][0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                "import operator",
            ),
            (
                "import operator\nd={Mut:1}\n"
                "e=[getattr(operator,'methodcaller')('copy')][::][0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                "import operator",
            ),
            (
                "from functools import partial\nimport copy\nd={Mut:1}\n"
                "e=[partial(copy.copy,d)][:1][0]()\ne|={}\nC,=e.keys()\nC()",
                "from functools import partial\nimport copy",
            ),
            (
                "from functools import partial\nimport copy\nd={Mut:1}\n"
                "e=[partial(copy.deepcopy,d)][:1][0]()\ne|={}\nC,=e.keys()\nC()",
                "from functools import partial\nimport copy",
            ),
            (
                "from functools import partial\nimport copy\nd={Mut:1}\n"
                "e=[partial(getattr(copy,'copy'))][:1][0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                "from functools import partial\nimport copy",
            ),
            (
                "from functools import partial\nimport copy\nd={Mut:1}\n"
                "e=[partial(getattr(copy,'copy'))][0:1][0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                "from functools import partial\nimport copy",
            ),
        )
    )


def test_sixteenth_pass_alias_packed_getattr_mutate_never_authorized() -> None:
    """Packed getattr itemgetter + Assign/packed/methodcaller/ior/copy mutate."""

    cases = (
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'k=[getattr(operator,"itemgetter")][0]("x")(keys)\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'k=(0 or getattr(operator,"itemgetter"))("x")(keys)\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'k=(getattr(operator,"itemgetter") if True else None)("x")(keys)\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'k=next(iter([getattr(operator,"itemgetter")]))("x")(keys)\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'mut=operator.setitem\nmut(keys,"z",keys.pop("x"))\nk=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        '[operator.setitem][0](keys,"z",keys.pop("x"))\nk=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'operator.methodcaller("__setitem__","z",keys.pop("x"))(keys)\n'
        'k=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'operator.ior(keys, {"z": keys.pop("x")})\nk=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'c=copy.copy(keys)\nc["z"]=c.pop("x")\nk=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
    )
    for body in cases:
        findings = _unit(
            "import helpers\nimport types, operator, copy\n"
            "def evil(state, value):\n"
            "    state.bypass_filter = value\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_sixteenth_pass_identity_name_bound_list_sort_never_authorized() -> None:
    """Name-bound unbound L.sort after from-import list as L (+ packs)."""

    _assert_ninth_not_authorized(
        (
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g=L.sort\ng(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g=L.sort\ng.__call__(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g=L.sort\n[g][0](xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g=L.sort\n(False or g)(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g=L.sort\n(g if True else len)(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g=L.sort\n{0:g}[0](xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g=L.sort\nnext(iter([g]))(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g: object = L.sort\ng(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "h=L\ng=h.sort\ng(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as List\nxs=[Mut]\n"
                "g=List.sort\ng(xs, key=type.__call__)",
                "from builtins import list as List",
            ),
            (
                "from builtins import list as lst\nxs=[Mut]\n"
                "g=lst.sort\ng(xs, key=type.__call__)",
                "from builtins import list as lst",
            ),
        )
    )


def test_sixteenth_pass_interproc_pop_slice_never_authorized() -> None:
    """Negative/bitwise pop + methodcaller getitem + copy|deepcopy slice packs."""

    _assert_ninth_not_authorized(
        (
            (
                "import copy\nd={Mut:1}\nviews=copy.copy([{'v':d.keys}])\n"
                "C,=views.pop(-1)['v']()\nC()",
                "import copy",
            ),
            (
                "import copy\nd={Mut:1}\nviews=copy.copy([{'v':d.keys}])\n"
                "C,=views.pop(~0)['v']()\nC()",
                "import copy",
            ),
            (
                "import copy\nd={Mut:1}\nviews=copy.copy([{'v':d.keys}])\n"
                "C,=list.pop(views,-1)['v']()\nC()",
                "import copy",
            ),
            (
                "from operator import methodcaller\nimport copy\n"
                "d={Mut:1}\nviews=copy.copy([{'v':d.keys}])\n"
                "C,=methodcaller('pop',-1)(views)['v']()\nC()",
                "from operator import methodcaller\nimport copy",
            ),
        )
    )
    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    for call in (
        "from operator import methodcaller; import copy; "
        "views=copy.copy([n.install]); methodcaller('__getitem__',0)(views)(evil)",
        "from operator import methodcaller; import copy; "
        "views=copy.copy([n.install]); "
        "[methodcaller('__getitem__',0)][0](views)(evil)",
        "import copy; copy.deepcopy([n.install])[:][0](evil)",
        "import copy; copy.copy([n.install])[:][0](evil)",
        "import copy; [copy.deepcopy][0]([n.install])[:][0](evil)",
        "import copy; [copy.deepcopy([n.install])][:1][0](evil)",
        "import copy; [copy.deepcopy([n.install])][0:1][0](evil)",
        "import copy; [copy.deepcopy([n.install])][::][0](evil)",
        "import copy; list(copy.deepcopy([n.install]))[:][0](evil)",
        "from copy import deepcopy as dc; dc([n.install])[:][0](evil)",
        "import copy; fn=copy.deepcopy; fn([n.install])[:][0](evil)",
    ):
        routes = f"""
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {call}
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        files = {
            "app/helpers.py": _helpers_source(),
            "app/pkg/__init__.py": "",
            "app/pkg/nested.py": nested,
            "app/routes.py": routes.strip(),
        }
        findings = analyze_bypass_authority_unit(
            files,
            entry_path="app/routes.py",
            function_name="handler",
            bypass_fields=frozenset({"bypass_filter"}),
            scope_proof=_scope(*files, import_roots=("app",)),
        )
        assert findings[0].status != "authorized", call
        assert findings[0].reason != "source_proved_server_authority_write", call


def test_sixteenth_pass_cf_packed_attrgetter_ior_setitem_never_authorized() -> None:
    """Packed attrgetter/__ior__/setitem/__dict__/partial(setitem) CF peels."""

    ex = _NINTH_EXEC
    imp = (
        "from collections import ChainMap\nimport operator, types\n"
        "from operator import methodcaller, attrgetter\n"
        "from functools import partial\nfrom builtins import list as L"
    )
    _assert_ninth_not_authorized(
        tuple(
            (c, imp)
            for c in (
                f'cm=ChainMap()\n[attrgetter("maps")][0](cm).append({{"e":exec}})\n'
                f'cm["e"]({ex})',
                f'cm=ChainMap()\n(0 or attrgetter("maps"))(cm).append({{"e":exec}})\n'
                f'cm["e"]({ex})',
                f'cm=ChainMap()\n'
                f'(attrgetter("maps") if True else None)(cm).append({{"e":exec}})\n'
                f'cm["e"]({ex})',
                f'cm=ChainMap()\n'
                f'[operator.attrgetter("maps")][0](cm).append({{"e":exec}})\n'
                f'cm["e"]({ex})',
                f'cm=ChainMap()\n'
                f'(0 or operator.attrgetter)("maps")(cm).append({{"e":exec}})\n'
                f'cm["e"]({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'operator.__ior__(vars(ns), {{"e":exec}})\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'[operator.__ior__][0](vars(ns), {{"e":exec}})\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'[getattr(operator,"__ior__")][0](vars(ns), {{"e":exec}})\n'
                f'ns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'[operator.setitem][0](vars(ns), "e", exec)\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'(0 or operator.setitem)(vars(ns), "e", exec)\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'(operator.setitem if True else None)(vars(ns), "e", exec)\n'
                f'ns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'object.__getattribute__(ns,"__dict__").update({{"e":exec}})\n'
                f'ns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'attrgetter("__dict__")(ns).update({{"e":exec}})\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'[partial(operator.setitem, vars(ns), "e")][0](exec)\n'
                f'ns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'(0 or partial(operator.setitem, vars(ns), "e"))(exec)\n'
                f'ns.e({ex})',
            )
        )
    )


def test_sixteenth_pass_class_methodcaller_kwargs_vars_never_authorized() -> None:
    """methodcaller __setattr__/kwargs update/Name-bound mc/vars |= peels."""

    mut = (
        "class Mut:\n"
        "    def __init__(self):\n"
        "        helpers.write_state = evil\n"
        "    @classmethod\n"
        "    def make(cls):\n"
        "        return cls()\n"
    )
    cases = (
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'methodcaller("__setattr__","m",Mut.make)(ns)\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'methodcaller("__setattr__","e",exec)(ns)\n'
        + f'ns.e({_NINTH_EXEC})',
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'methodcaller("update", m=Mut.make)(vars(ns))\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'methodcaller("update", m=Mut.make)(ns.__dict__)\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'mc=operator.methodcaller\n'
        + 'mc("__setattr__","m",Mut.make)(ns)\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'd=vars(ns)\nd|={"m": Mut.make}\nns.m()',
    )
    for body in cases:
        findings = _unit(
            _ninth_src(
                body,
                imports=(
                    "import types\nimport operator\n"
                    "from operator import methodcaller"
                ),
            )
        )
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_sixteenth_pass_positive_authorized_smoke() -> None:
    """Benign analogues of sixteenth-pass shapes remain authorized."""

    for body in (
        "from functools import partial\nimport copy\nd={}\n"
        "e=[partial(copy.copy,d)][:1][0]()\ne|={}\nlen(e)",
        "from builtins import list as L\nxs=[1]\ng=L.sort\ng(xs, key=lambda x: x)",
        "import copy\nd={}\nviews=copy.copy([{'v':d.keys}])\nlen(views.pop(-1))",
        "from collections import ChainMap\nfrom operator import attrgetter\n"
        'cm=ChainMap()\n[attrgetter("maps")][0](cm).append({})\nlen(cm)',
        "import types, operator\nns=types.SimpleNamespace()\n"
        'operator.__ior__(vars(ns), {"x":1})\nns.x',
        "import types\nfrom operator import methodcaller\n"
        'ns=types.SimpleNamespace()\n'
        'methodcaller("__setattr__","x",1)(ns)\nns.x',
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'k=[getattr(operator,"itemgetter")][0]("x")(keys)\n'
        'Proxy=getattr(ns,"get")(k)\nProxy({})',
    ):
        src = (
            "import helpers\nimport copy\nimport types\nimport operator\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status == "authorized", body
        assert findings[0].reason == "source_proved_server_authority_write", body


def test_seventeenth_pass_lexical_slice_object_pack_never_authorized() -> None:
    """Call/Name ``slice`` products + getitem/__getitem__ packing peels."""

    _assert_ninth_not_authorized(
        (
            (
                "import operator\nd={Mut:1}\n"
                "e=[getattr(operator,'methodcaller')('copy')][slice(0,1)][0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                "import operator",
            ),
            (
                "import operator\nd={Mut:1}\n"
                "e=operator.getitem([getattr(operator,'methodcaller')('copy')], "
                "slice(0,1))[0](d)\ne|={}\nC,=e.keys()\nC()",
                "import operator",
            ),
            (
                "import operator\nd={Mut:1}\n"
                "e=list.__getitem__([getattr(operator,'methodcaller')('copy')], "
                "slice(0,1))[0](d)\ne|={}\nC,=e.keys()\nC()",
                "import operator",
            ),
            (
                "import operator\nd={Mut:1}\n"
                "xs=[getattr(operator,'methodcaller')('copy')]\n"
                "e=xs.__getitem__(slice(0,1))[0](d)\ne|={}\nC,=e.keys()\nC()",
                "import operator",
            ),
            (
                "import operator\nd={Mut:1}\ns=slice(0,1)\n"
                "e=[getattr(operator,'methodcaller')('copy')][s][0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                "import operator",
            ),
            (
                "import operator\nimport builtins\nd={Mut:1}\n"
                "e=[getattr(operator,'methodcaller')('copy')]"
                "[builtins.slice(0,1)][0](d)\ne|={}\nC,=e.keys()\nC()",
                "import operator\nimport builtins",
            ),
            (
                "import operator\nimport builtins\nd={Mut:1}\n"
                "e=[getattr(operator,'methodcaller')('copy')]"
                "[getattr(builtins,'slice')(0,1)][0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                "import operator\nimport builtins",
            ),
            (
                "from functools import partial\nimport copy\nd={Mut:1}\n"
                "e=[partial(getattr(copy,'copy'))][slice(0,1)][0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                "from functools import partial\nimport copy",
            ),
            (
                "import operator\nd={Mut:1}\n"
                "e=next(iter([getattr(operator,'methodcaller')('copy')]"
                "[slice(None,1)]))(d)\ne|={}\nC,=e.keys()\nC()",
                "import operator",
            ),
            (
                "import operator\nd={Mut:1}\n"
                "e=[*([getattr(operator,'methodcaller')('copy')]"
                "[slice(0,1)])][0](d)\ne|={}\nC,=e.keys()\nC()",
                "import operator",
            ),
        )
    )


def test_seventeenth_pass_identity_list_sort_seed_never_authorized() -> None:
    """getattr/builtins.list/dict-mid/BoolOp/IfExp/attrgetter sort packs."""

    _assert_ninth_not_authorized(
        (
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g=getattr(L,'sort')\n[g][0](xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g=getattr(L,'sort')\n(0 or g)(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g=getattr(L,'sort')\n{0:g}[0](xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g=getattr(L,'sort')\nnext(iter([g]))(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "import builtins\nL=builtins.list\nxs=[Mut]\n"
                "g=L.sort\ng(xs, key=type.__call__)",
                "import builtins",
            ),
            (
                "import builtins\nL=getattr(builtins,'list')\nxs=[Mut]\n"
                "g=L.sort\ng(xs, key=type.__call__)",
                "import builtins",
            ),
            (
                "import builtins\nL=builtins.__dict__['list']\nxs=[Mut]\n"
                "L.sort(xs, key=type.__call__)",
                "import builtins",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "p={0:L.sort}\ng=p[0]\ng(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "p={0:getattr(L,'sort')}\ng=p[0]\ng(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g=(0 or L).sort\ng(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "g=(L if True else list).sort\ng(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from operator import attrgetter\nfrom builtins import list as L\n"
                "xs=[Mut]\ng=attrgetter('sort')(L)\n[g][0](xs, key=type.__call__)",
                "from operator import attrgetter\nfrom builtins import list as L",
            ),
        )
    )


def test_seventeenth_pass_class_kwargs_update_never_authorized() -> None:
    """methodcaller/update ``**kwargs`` on vars/__dict__/attrgetter peels."""

    mut = (
        "class Mut:\n"
        "    def __init__(self):\n"
        "        helpers.write_state = evil\n"
        "    @classmethod\n"
        "    def make(cls):\n"
        "        return cls()\n"
    )
    cases = (
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'methodcaller("update", **{"m": Mut.make})(vars(ns))\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'methodcaller("update", **{"m": Mut.make})(ns.__dict__)\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'from operator import attrgetter\n'
        + 'methodcaller("update", **{"m": Mut.make})(attrgetter("__dict__")(ns))\n'
        + "ns.m()",
        mut
        + 'ns=types.SimpleNamespace()\nkw={"m": Mut.make}\n'
        + 'methodcaller("update", **kw)(vars(ns))\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'mc=operator.methodcaller\n'
        + 'mc("update", **{"m": Mut.make})(vars(ns))\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'mc=(0 or operator.methodcaller)\n'
        + 'mc("update", **{"m": Mut.make})(vars(ns))\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\nkw={"m": Mut.make}\n'
        + "d=vars(ns)\nd.update(**kw)\nns.m()",
        mut
        + 'ns=types.SimpleNamespace()\nkw={"m": Mut.make}\n'
        + "(d:=vars(ns)).update(**kw)\nns.m()",
        mut
        + 'ns=types.SimpleNamespace()\nkw={"m": Mut.make}\n'
        + "dict.update(vars(ns), **kw)\nns.m()",
        mut
        + 'ns=types.SimpleNamespace()\nkw={"m": Mut.make}\n'
        + "builtins.dict.update(vars(ns), **kw)\nns.m()",
    )
    for body in cases:
        findings = _unit(
            _ninth_src(
                body,
                imports=(
                    "import types\nimport operator\nimport builtins\n"
                    "from operator import methodcaller"
                ),
            )
        )
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_seventeenth_pass_interproc_pop_partial_never_authorized() -> None:
    """BoolOp/IfExp/Name/walrus ``.pop`` + packed partial(copy) slice peels."""

    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    for call in (
        "import copy; views=copy.copy([n.install]); (0 or views.pop)(-1)(evil)",
        "import copy; views=copy.copy([n.install]); "
        "(views.pop if True else None)(-1)(evil)",
        "import copy; views=copy.copy([n.install]); p=views.pop; p(-1)(evil)",
        "import copy; views=copy.copy([n.install]); (p:=views.pop)(-1)(evil)",
        "from functools import partial; import copy; "
        "[partial(copy.deepcopy)][0]([n.install])[:][0](evil)",
        "from functools import partial; import copy; "
        "[partial(copy.copy)][0]([n.install])[:][0](evil)",
        "from functools import partial; import copy; "
        "(0 or partial(copy.deepcopy))([n.install])[:][0](evil)",
        "from functools import partial; import copy; "
        "(partial(copy.deepcopy) if True else None)([n.install])[:][0](evil)",
        "from functools import partial; import copy; "
        "next(iter([partial(copy.deepcopy)]))([n.install])[:][0](evil)",
    ):
        routes = f"""
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {call}
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        files = {
            "app/helpers.py": _helpers_source(),
            "app/pkg/__init__.py": "",
            "app/pkg/nested.py": nested,
            "app/routes.py": routes.strip(),
        }
        findings = analyze_bypass_authority_unit(
            files,
            entry_path="app/routes.py",
            function_name="handler",
            bypass_fields=frozenset({"bypass_filter"}),
            scope_proof=_scope(*files, import_roots=("app",)),
        )
        assert findings[0].status != "authorized", call
        assert findings[0].reason != "source_proved_server_authority_write", call


def test_seventeenth_pass_cf_packed_partial_setattr_never_authorized() -> None:
    """Packed/BoolOp/IfExp/slice/next partial(setattr|object.__setattr__) CF."""

    ex = _NINTH_EXEC
    imp = (
        "import types\nfrom functools import partial\n"
        "from builtins import setattr as SA\nimport builtins"
    )
    _assert_ninth_not_authorized(
        tuple(
            (c, imp)
            for c in (
                f'ns=types.SimpleNamespace()\n'
                f'[partial(setattr, ns, "e")][0](exec)\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'(0 or partial(setattr, ns, "e"))(exec)\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'(partial(setattr, ns, "e") if True else None)(exec)\n'
                f'ns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'[partial(setattr, ns, "e")][slice(0,1)][0](exec)\n'
                f'ns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'next(iter([partial(setattr, ns, "e")]))(exec)\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'[*([partial(setattr, ns, "e")])][0](exec)\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'[partial(object.__setattr__, ns, "e")][0](exec)\n'
                f'ns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'[partial(SA, ns, "e")][0](exec)\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'[partial(getattr(builtins,"setattr"), ns, "e")][0](exec)\n'
                f'ns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'if [partial(setattr, ns, "e")][0](exec):\n    pass\n'
                f'ns.e({ex})',
            )
        )
    )


def test_seventeenth_pass_alias_name_bind_copy_mutate_never_authorized() -> None:
    """Assign packed itemgetter / Name-bound mc / __ior__ / copy-then-mutate."""

    cases = (
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'ig=[getattr(operator,"itemgetter")][0]("x")\nk=ig(keys)\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'ig: object = [getattr(operator,"itemgetter")][0]("x")\nk=ig(keys)\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'prod=[getattr(operator,"itemgetter")][0]("x")\nk=prod(keys)\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'ig=next(iter([getattr(operator,"itemgetter")]))("x")\nk=ig(keys)\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'mc=operator.methodcaller("__setitem__","z",keys.pop("x"))\nmc(keys)\n'
        'k=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'mc=getattr(operator,"methodcaller")("__setitem__","z",keys.pop("x"))\n'
        'mc(keys)\nk=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'mc=[operator.methodcaller][0]("__setitem__","z",keys.pop("x"))\n'
        'mc(keys)\nk=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'keys.__ior__({"z": keys.pop("x")})\nk=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'mut=getattr(operator,"__ior__"); mut(keys, {"z": keys.pop("x")})\n'
        'k=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'c=getattr(copy,"copy")(keys)\nc["z"]=c.pop("x")\nk=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'c=[copy.copy][0](keys)\nc["z"]=c.pop("x")\nk=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'c=(0 or copy.copy)(keys)\nc["z"]=c.pop("x")\nk=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'c=next(iter([copy.copy]))(keys)\nc["z"]=c.pop("x")\nk=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'c=operator.methodcaller("copy")(keys)\nc["z"]=c.pop("x")\nk=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'from functools import partial\n'
        'c=partial(copy.copy,keys)()\nc["z"]=c.pop("x")\nk=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'c=dict(keys)\nc["z"]=c.pop("x")\nk=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'c=getattr(dict,"copy")(keys)\nc["z"]=c.pop("x")\nk=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
    )
    for body in cases:
        findings = _unit(
            "import helpers\nimport types, operator, copy\n"
            "def evil(state, value):\n"
            "    state.bypass_filter = value\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_seventeenth_pass_positive_authorized_smoke() -> None:
    """Benign analogues of seventeenth-pass shapes remain authorized."""

    for body in (
        "import operator\nd={}\n"
        "e=[getattr(operator,'methodcaller')('copy')][slice(0,1)][0](d)\n"
        "e|={}\nlen(e)",
        "from builtins import list as L\nxs=[1]\n"
        "g=getattr(L,'sort')\n[g][0](xs, key=lambda x: x)",
        "import types\nfrom operator import methodcaller\n"
        'ns=types.SimpleNamespace()\n'
        'methodcaller("update", **{"x":1})(vars(ns))\nns.x',
        "import copy\nviews=copy.copy([{'v':1}])\n"
        "p=views.pop; len(p(-1))",
        "import types\nfrom functools import partial\n"
        'ns=types.SimpleNamespace()\n'
        '[partial(setattr, ns, "x")][0](1)\nns.x',
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'ig=[getattr(operator,"itemgetter")][0]("x")\nk=ig(keys)\n'
        'Proxy=getattr(ns,"get")(k)\nProxy({})',
    ):
        src = (
            "import helpers\nimport copy\nimport types\nimport operator\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status == "authorized", body
        assert findings[0].reason == "source_proved_server_authority_write", body


def test_eighteenth_pass_identity_getattr_list_partial_get_never_authorized() -> None:
    """BoolOp/IfExp getattr, ns.get list, applied attrgetter, partial/__get__."""

    _assert_ninth_not_authorized(
        (
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "(0 or getattr)(L,'sort')(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "from builtins import list as L\nxs=[Mut]\n"
                "(getattr if True else None)(L,'sort')(xs, key=type.__call__)",
                "from builtins import list as L",
            ),
            (
                "import builtins\nL=vars(builtins).get('list')\nxs=[Mut]\n"
                "L.sort(xs, key=type.__call__)",
                "import builtins",
            ),
            (
                "import builtins\nL=builtins.__dict__.get('list')\nxs=[Mut]\n"
                "L.sort(xs, key=type.__call__)",
                "import builtins",
            ),
            (
                "import builtins\nL=builtins.__dict__.__getitem__('list')\n"
                "xs=[Mut]\nL.sort(xs, key=type.__call__)",
                "import builtins",
            ),
            (
                "import builtins\ng=builtins.__dict__.get\nL=g('list')\n"
                "xs=[Mut]\nL.sort(xs, key=type.__call__)",
                "import builtins",
            ),
            (
                "import builtins\nL=(0 or builtins.__dict__.get)('list')\n"
                "xs=[Mut]\nL.sort(xs, key=type.__call__)",
                "import builtins",
            ),
            (
                "import builtins\nL=getattr(builtins.__dict__,'get')('list')\n"
                "xs=[Mut]\nL.sort(xs, key=type.__call__)",
                "import builtins",
            ),
            (
                "from operator import attrgetter\nfrom builtins import list as L\n"
                "xs=[Mut]\nnext(iter([attrgetter('sort')(L)]))(xs, key=type.__call__)",
                "from operator import attrgetter\nfrom builtins import list as L",
            ),
            (
                "from operator import attrgetter\nfrom builtins import list as L\n"
                "xs=[Mut]\n[*([attrgetter('sort')(L)])][0](xs, key=type.__call__)",
                "from operator import attrgetter\nfrom builtins import list as L",
            ),
            (
                "from operator import attrgetter\nfrom builtins import list as L\n"
                "xs=[Mut]\n[attrgetter('sort')(L)][:1][0](xs, key=type.__call__)",
                "from operator import attrgetter\nfrom builtins import list as L",
            ),
            (
                "from functools import partial\nfrom builtins import list as L\n"
                "xs=[Mut]\n[partial(L.sort, xs)][0](key=type.__call__)",
                "from functools import partial\nfrom builtins import list as L",
            ),
            (
                "from functools import partial\nxs=[Mut]\n"
                "(0 or partial(list.sort, xs))(key=type.__call__)",
                "from functools import partial",
            ),
            (
                "from functools import partial\nfrom builtins import list as L\n"
                "xs=[Mut]\n(partial(L.sort, xs) if True else None)(key=type.__call__)",
                "from functools import partial\nfrom builtins import list as L",
            ),
            (
                "from functools import partial\nxs=[Mut]\n"
                "next(iter([partial(list.sort, xs)]))(key=type.__call__)",
                "from functools import partial",
            ),
            (
                "g=list.sort.__get__(None, list)\nxs=[Mut]\n"
                "g(xs, key=type.__call__)",
                "",
            ),
            (
                "g=list.__dict__['sort'].__get__(None, list)\nxs=[Mut]\n"
                "g(xs, key=type.__call__)",
                "",
            ),
            (
                "g=(0 or list.sort.__get__)(None, list)\nxs=[Mut]\n"
                "g(xs, key=type.__call__)",
                "",
            ),
            (
                "g=getattr(list.sort,'__get__')(None, list)\nxs=[Mut]\n"
                "g(xs, key=type.__call__)",
                "",
            ),
        )
    )


def test_eighteenth_pass_lexical_packed_partial_getitem_never_authorized() -> None:
    """Packed partial(getitem|__getitem__, xs, slice) / methodcaller peels."""

    lex_imp = "import operator\nfrom functools import partial"
    _assert_ninth_not_authorized(
        (
            (
                "d={Mut:1}\nxs=[getattr(operator,'methodcaller')('copy')]\n"
                "e=[partial(operator.getitem, xs, slice(0,1))][0]()[0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                lex_imp,
            ),
            (
                "d={Mut:1}\nxs=[getattr(operator,'methodcaller')('copy')]\n"
                "e=next(iter([partial(operator.getitem, xs, slice(0,1))]))()[0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                lex_imp,
            ),
            (
                "d={Mut:1}\nxs=[getattr(operator,'methodcaller')('copy')]\n"
                "e=(0 or partial(operator.getitem, xs, slice(0,1)))()[0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                lex_imp,
            ),
            (
                "d={Mut:1}\nxs=[getattr(operator,'methodcaller')('copy')]\n"
                "e=(partial(operator.getitem, xs, slice(0,1)) if True else None)"
                "()[0](d)\ne|={}\nC,=e.keys()\nC()",
                lex_imp,
            ),
            (
                "d={Mut:1}\nxs=[getattr(operator,'methodcaller')('copy')]\n"
                "e=[*([partial(operator.getitem, xs, slice(0,1))])][0]()[0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                lex_imp,
            ),
            (
                "d={Mut:1}\nxs=[getattr(operator,'methodcaller')('copy')]\n"
                "e=[partial(list.__getitem__, xs, slice(0,1))][0]()[0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                lex_imp,
            ),
            (
                "d={Mut:1}\nxs=[getattr(operator,'methodcaller')('copy')]\n"
                "e=[partial(getattr(operator,'getitem'), xs, slice(0,1))][0]()"
                "[0](d)\ne|={}\nC,=e.keys()\nC()",
                lex_imp,
            ),
            (
                "d={Mut:1}\nxs=[getattr(operator,'methodcaller')('copy')]\n"
                "e=[partial(operator.getitem, xs)][0](slice(0,1))[0](d)\n"
                "e|={}\nC,=e.keys()\nC()",
                lex_imp,
            ),
            (
                "d={Mut:1}\nxs=[getattr(operator,'methodcaller')('copy')]\n"
                "e=[partial(operator.methodcaller('__getitem__', slice(0,1)), xs)]"
                "[0]()[0](d)\ne|={}\nC,=e.keys()\nC()",
                lex_imp,
            ),
            (
                "d={Mut:1}\nxs=[getattr(operator,'methodcaller')('copy')]\n"
                "e=[partial(operator.getitem, xs, 0)][0]()(d)\ne|={}\nC,=e.keys()\nC()",
                lex_imp,
            ),
        )
    )


def test_eighteenth_pass_cf_name_binop_partial_setattr_never_authorized() -> None:
    """Name→next/reversed/values and BinOp/concat peels after partial(setattr)."""

    ex = _NINTH_EXEC
    cf_imp = (
        "import types\nfrom functools import partial\n"
        "from builtins import setattr as SA\nimport builtins\nimport operator"
    )
    _assert_ninth_not_authorized(
        tuple(
            (c, cf_imp)
            for c in (
                f'ns=types.SimpleNamespace()\np=partial(setattr, ns, "e")\n'
                f"next(iter([p]))(exec)\nns.e({ex})",
                f'ns=types.SimpleNamespace()\np=partial(setattr, ns, "e")\n'
                f"next(reversed([p]))(exec)\nns.e({ex})",
                f'ns=types.SimpleNamespace()\np=partial(setattr, ns, "e")\n'
                f"next(iter({{0:p}}.values()))(exec)\nns.e({ex})",
                f'ns=types.SimpleNamespace()\n'
                f'([partial(setattr, ns, "e")]+[])[0](exec)\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'([]+[partial(setattr, ns, "e")])[0](exec)\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'([partial(setattr, ns, "e")]*1)[0](exec)\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'((partial(setattr, ns, "e"),)+())[0](exec)\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'operator.concat([partial(setattr, ns, "e")], [])[0](exec)\n'
                f"ns.e({ex})",
                f'ns=types.SimpleNamespace()\n'
                f'[partial(setattr, ns, "e")].__add__([])[0](exec)\nns.e({ex})',
                f'ns=types.SimpleNamespace()\n'
                f'[partial(operator.methodcaller("__setattr__","e",exec))][0](ns)\n'
                f"ns.e({ex})",
                f'ns=types.SimpleNamespace()\n'
                f'if next(iter([p:=partial(setattr, ns, "e")]))(exec):\n'
                f"    pass\nns.e({ex})",
            )
        )
    )


def test_eighteenth_pass_alias_name_product_copy_setitem_never_authorized() -> None:
    """Name-bound ig/mc/partial apply, walrus copy-mutate, getattr/partial setitem."""

    cases = (
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'ig=[getattr(operator,"itemgetter")][0]("x"); k=next(iter([ig]))(keys)\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'ig=[getattr(operator,"itemgetter")][0]("x")\n'
        "k=next(iter([(ig if True else None)]))(keys)\n"
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'mc=operator.methodcaller("copy"); c=mc(keys); c["z"]=c.pop("x")\n'
        'k=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'mc: object = operator.methodcaller("copy"); c=mc(keys)\n'
        'c["z"]=c.pop("x"); k=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'mc=getattr(operator,"methodcaller")("copy"); c=(0 or mc)(keys)\n'
        'c["z"]=c.pop("x"); k=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        "from functools import partial\n"
        'p=partial(copy.copy,keys); c=p(); c["z"]=c.pop("x")\n'
        'k=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        "from functools import partial\n"
        'p: object = partial(copy.copy,keys); c=(0 or p)()\n'
        'c["z"]=c.pop("x"); k=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        '(c:=getattr(copy,"copy")(keys))["z"]=c.pop("x")\n'
        'k=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        '(c:=[copy.copy][0](keys))["z"]=c.pop("x")\n'
        'k=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'getattr(keys,"__setitem__")("z", keys.pop("x"))\n'
        'k=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        "from functools import partial\n"
        'partial(operator.setitem, keys, "z")(keys.pop("x"))\n'
        'k=keys.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
    )
    for body in cases:
        findings = _unit(
            "import helpers\nimport types, operator, copy\n"
            "def evil(state, value):\n"
            "    state.bypass_filter = value\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_eighteenth_pass_class_getattr_update_spread_never_authorized() -> None:
    """getattr(dict,\"update\") + **(IfExp|BoolOp) kwargs spreads."""

    mut = (
        "class Mut:\n"
        "    def __init__(self):\n"
        "        helpers.write_state = evil\n"
        "    @classmethod\n"
        "    def make(cls):\n"
        "        return cls()\n"
    )
    cases = (
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'getattr(dict,"update")(vars(ns), **{"m": Mut.make})\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\nd=vars(ns)\n'
        + 'getattr(dict,"update")(d, m=Mut.make)\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'getattr(dict,"update")(ns.__dict__, **{"m": Mut.make})\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\nfrom operator import attrgetter\n'
        + 'getattr(dict,"update")(attrgetter("__dict__")(ns), m=Mut.make)\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\nkw={"m": Mut.make}\n'
        + 'methodcaller("update", **(kw if True else {}))(vars(ns))\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\nkw={"m": Mut.make}\n'
        + 'methodcaller("update", **(kw or {}))(vars(ns))\nns.m()',
        mut
        + 'ns=types.SimpleNamespace()\n'
        + 'methodcaller("update", **({"m": Mut.make} if True else {}))'
        "(vars(ns))\nns.m()",
        mut
        + 'ns=types.SimpleNamespace()\nkw={"m": Mut.make}\n'
        + "d=vars(ns)\nd.update(**(kw if True else {}))\nns.m()",
        mut
        + 'ns=types.SimpleNamespace()\nkw={"m": Mut.make}\n'
        + "dict.update(vars(ns), **(kw if True else {}))\nns.m()",
        mut
        + 'ns=types.SimpleNamespace()\nkw={"m": Mut.make}\n'
        + "builtins.dict.update(vars(ns), **(kw or {}))\nns.m()",
    )
    for body in cases:
        findings = _unit(
            _ninth_src(
                body,
                imports=(
                    "import types\nimport operator\nimport builtins\n"
                    "from operator import methodcaller"
                ),
            )
        )
        assert findings[0].status != "authorized", body
        assert findings[0].reason != "source_proved_server_authority_write", body


def test_eighteenth_pass_interproc_seventeenth_stays_closed() -> None:
    """Interproc seventeenth BoolOp/Name/walrus pop + packed partial copy."""

    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    for call in (
        "import copy; views=copy.copy([n.install]); (0 or views.pop)(-1)(evil)",
        "import copy; views=copy.copy([n.install]); "
        "(views.pop if True else None)(-1)(evil)",
        "import copy; views=copy.copy([n.install]); p=views.pop; p(-1)(evil)",
        "import copy; views=copy.copy([n.install]); (p:=views.pop)(-1)(evil)",
        "from functools import partial; import copy; "
        "[partial(copy.deepcopy)][0]([n.install])[:][0](evil)",
        "from functools import partial; import copy; "
        "[partial(copy.copy)][0]([n.install])[:][0](evil)",
        "from functools import partial; import copy; "
        "(0 or partial(copy.deepcopy))([n.install])[:][0](evil)",
        "from functools import partial; import copy; "
        "(partial(copy.deepcopy) if True else None)([n.install])[:][0](evil)",
        "from functools import partial; import copy; "
        "next(iter([partial(copy.deepcopy)]))([n.install])[:][0](evil)",
    ):
        routes = f"""
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {call}
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        files = {
            "app/helpers.py": _helpers_source(),
            "app/pkg/__init__.py": "",
            "app/pkg/nested.py": nested,
            "app/routes.py": routes.strip(),
        }
        findings = analyze_bypass_authority_unit(
            files,
            entry_path="app/routes.py",
            function_name="handler",
            bypass_fields=frozenset({"bypass_filter"}),
            scope_proof=_scope(*files, import_roots=("app",)),
        )
        assert findings[0].status != "authorized", call
        assert findings[0].reason != "source_proved_server_authority_write", call


def test_eighteenth_pass_positive_authorized_smoke() -> None:
    """Benign analogues of eighteenth-pass shapes remain authorized."""

    for body in (
        "from builtins import list as L\nxs=[1]\n"
        "(0 or getattr)(L,'sort')(xs, key=lambda x: x)",
        "import operator\nfrom functools import partial\nd={}\n"
        "xs=[getattr(operator,'methodcaller')('copy')]\n"
        "e=[partial(operator.getitem, xs, slice(0,1))][0]()[0](d)\n"
        "e|={}\nlen(e)",
        "import types\nfrom functools import partial\n"
        'ns=types.SimpleNamespace()\n'
        'p=partial(setattr, ns, "x"); next(iter([p]))(1)\nns.x',
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        'ig=[getattr(operator,"itemgetter")][0]("x")\n'
        "k=next(iter([ig]))(keys)\n"
        'Proxy=getattr(ns,"get")(k)\nProxy({})',
        "import types\nfrom operator import methodcaller\n"
        'ns=types.SimpleNamespace()\nkw={"x":1}\n'
        'methodcaller("update", **(kw if True else {}))(vars(ns))\nns.x',
    ):
        src = (
            "import helpers\nimport copy\nimport types\nimport operator\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        findings = _unit(src)
        assert findings[0].status == "authorized", body
        assert findings[0].reason == "source_proved_server_authority_write", body


def test_persistent_version_bumped_for_executed_expr_closure() -> None:
    """Cache / semantic versions bump with PASS-semantics change."""

    assert PERSISTENT_FASTAPI_STATE_IMPLEMENTATION_VERSION == "0.70.0"
