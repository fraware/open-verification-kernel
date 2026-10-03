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


def test_persistent_version_bumped_for_executed_expr_closure() -> None:
    """Cache / semantic versions bump with PASS-semantics change."""

    assert PERSISTENT_FASTAPI_STATE_IMPLEMENTATION_VERSION == "0.53.0"
