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


def test_persistent_version_bumped_for_executed_expr_closure() -> None:
    """Cache / semantic versions bump with PASS-semantics change."""

    assert PERSISTENT_FASTAPI_STATE_IMPLEMENTATION_VERSION == "0.43.0"
