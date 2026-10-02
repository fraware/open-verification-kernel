"""Request-time control-flow identity state joins (#169).

Closes false PASSes where branch-local re-establishment cleared shared
mutation poisons, and where ``ast.Match`` case bodies omitted client /
request-state writes from closed-world accounting.

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


def _safe_rebind_block(*, indent: int = 8, name: str = "write_state") -> str:
    pad = " " * indent
    return (
        f"{pad}def {name}(state, value):\n"
        f"{pad}    state.bypass_filter = True\n"
        f"{pad}helpers.write_state = {name}"
    )


def test_poison_before_if_reestablish_one_branch_only_is_unknown() -> None:
    """1. Poison before if; safe re-establish one branch only → UNKNOWN."""

    findings = _unit(
        f"""
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    if bypass_filter:
{_safe_rebind_block(indent=8)}
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_same_identity_reestablished_every_branch_may_establish() -> None:
    """2. Same identity re-established on every branch → may establish."""

    findings = _unit(
        f"""
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    if bypass_filter:
{_safe_rebind_block(indent=8)}
    else:
{_safe_rebind_block(indent=8)}
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status in {"authorized", "unknown"}
    if findings[0].status == "authorized":
        assert findings[0].reason == "source_proved_server_authority_write"


def test_different_safe_functions_on_branches_is_unknown() -> None:
    """3. Different safe functions on branches → UNKNOWN."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    if bypass_filter:
        def write_a(state, value):
            state.bypass_filter = True
        helpers.write_state = write_a
    else:
        def write_b(state, value):
            state.bypass_filter = True
        helpers.write_state = write_b
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_same_name_different_bodies_on_branches_is_unknown() -> None:
    """3b. Same nested name, different bodies on branches → UNKNOWN."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    if bypass_filter:
        def write_state(state, value):
            state.bypass_filter = True
        helpers.write_state = write_state
    else:
        def write_state(state, value):
            state.bypass_filter = bypass_filter
        helpers.write_state = write_state
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_poison_before_zero_iter_loop_reestablish_only_in_loop_is_unknown() -> None:
    """4. Poison before zero-iter loop; re-establish only in loop → UNKNOWN."""

    findings = _unit(
        f"""
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    for _ in []:
{_safe_rebind_block(indent=8)}
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_poison_before_try_reestablish_only_normal_path_is_unknown() -> None:
    """5. Poison before try; re-establish only normal path → UNKNOWN."""

    findings = _unit(
        f"""
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    try:
{_safe_rebind_block(indent=8)}
    except Exception:
        pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_poison_before_try_reestablish_only_except_path_is_unknown() -> None:
    """6. Poison before try; re-establish only except path → UNKNOWN."""

    findings = _unit(
        f"""
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    try:
        pass
    except Exception:
{_safe_rebind_block(indent=8)}
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_finally_unconditional_source_grounded_restoration() -> None:
    """7. finally unconditional source-grounded restoration → per theorem."""

    findings = _unit(
        f"""
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    try:
        x = 1
    finally:
{_safe_rebind_block(indent=8)}
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    # finally always runs: may re-establish, or stay UNKNOWN. Never false PASS
    # through the poisoned evil binding.
    assert findings[0].status in {"authorized", "unknown"}
    if findings[0].status == "authorized":
        assert findings[0].reason == "source_proved_server_authority_write"


def test_same_helper_distinct_identity_inputs_on_branches_analyzed() -> None:
    """8. Same helper under distinct identity inputs on two branches."""

    findings = _unit(
        """
import helpers
def evil(state, value):
    state.bypass_filter = value
def other_evil(state, value):
    state.bypass_filter = value
def poison_a():
    helpers.write_state = evil
def poison_b():
    helpers.write_state = other_evil
def handler(request, bypass_filter=False):
    if bypass_filter:
        poison_a()
    else:
        poison_b()
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    # Both branch identity inputs must be observed → post-join UNKNOWN.
    assert findings[0].status == "unknown"


def test_direct_client_write_inside_match_case_never_authorized() -> None:
    """9. Direct client write inside match case → never authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    match bypass_filter:
        case True:
            request.state.bypass_filter = bypass_filter
        case _:
            helpers.write_state(request.state, True)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_request_state_alias_write_inside_match_never_authorized() -> None:
    """10. Request/state alias write inside match → never authorized."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    state = request.state
    match bypass_filter:
        case True:
            state.bypass_filter = bypass_filter
        case _:
            helpers.write_state(request.state, True)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status != "authorized"
    assert findings[0].status in {"violated", "unknown"}


def test_helper_receiving_request_state_inside_match_analyzed_or_unknown() -> None:
    """11. Helper receiving request/state inside match → analyzed or UNKNOWN."""

    findings = _unit(
        """
import helpers
def handler(request, bypass_filter=False):
    match bypass_filter:
        case True:
            helpers.write_state(request.state, bypass_filter)
        case _:
            pass
    return request.state.bypass_filter
"""
    )
    assert findings[0].status in {"authorized", "unknown", "violated"}
    if findings[0].status == "authorized":
        assert findings[0].reason == "source_proved_server_authority_write"


def test_match_branch_identity_mutations_use_full_state_fork_join() -> None:
    """12. match branch identity mutations use full-state fork/join."""

    findings = _unit(
        f"""
import helpers
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    helpers.write_state = evil
    match bypass_filter:
        case True:
{_safe_rebind_block(indent=12)}
        case _:
            pass
    helpers.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
    )
    assert findings[0].status == "unknown"


def test_control_flow_join_full_equals_incremental() -> None:
    """13. full == incremental for control-flow join / match write cases."""

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
    helpers.write_state = evil
    if bypass_filter:
        def write_state(state, value):
            state.bypass_filter = True
        helpers.write_state = write_state
    helpers.write_state(request.state, bypass_filter)
    match bypass_filter:
        case True:
            request.state.bypass_filter = bypass_filter
        case _:
            pass
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
            repo="example/request-time-cf-joins",
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
