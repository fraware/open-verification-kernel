from __future__ import annotations

import ast
from pathlib import Path

from ovk.compilers.authorization.fastapi_route_summary import (
    CallSummary,
    summarize_route_file,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.persistent_fastapi_state import (
    PersistentFastApiIncrementalStateCache,
    compile_persistent_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.semantic_summary_cache import (
    PersistentPythonSemanticSummaryCache,
    load_persistent_semantic_summaries,
)
from ovk.core.protected_effect_evaluation import (
    evaluate_protected_effect_integrity,
)


def _summary(source: str):
    return summarize_route_file(
        path="routes.py",
        tree=ast.parse(source),
        source_digest="sha256:test",
    )


def _call(source: str, name: str) -> CallSummary:
    summary = _summary(source)
    assert len(summary.handlers) == 1
    matches = [
        call
        for call in summary.handlers[0].calls
        if call.leaf_name == name
    ]
    assert len(matches) == 1
    return matches[0]


def _condition_pairs(call: CallSummary) -> list[tuple[str, bool]]:
    return [
        (condition.expression, condition.truth_value)
        for condition in call.lexical_conditions
    ]


def test_true_and_branch_decomposes_into_exact_conjunctive_atoms() -> None:
    source = """
from fastapi import APIRouter

router = APIRouter()

@router.post("/chat")
def chat(bypass_filter: bool, user):
    if not bypass_filter and user.role == "user":
        protected_call()
""".strip()

    call = _call(source, "protected_call")

    assert _condition_pairs(call) == [
        ("bypass_filter", False),
        ("user.role == 'user'", True),
    ]
    assert all(
        condition.origin.source_range is not None
        for condition in call.lexical_conditions
    )


def test_false_or_branch_decomposes_into_exact_conjunctive_atoms() -> None:
    source = """
from fastapi import APIRouter

router = APIRouter()

@router.post("/chat")
def chat(is_admin: bool, is_owner: bool):
    if is_admin or is_owner:
        audit()
    else:
        protected_call()
""".strip()

    call = _call(source, "protected_call")

    assert _condition_pairs(call) == [
        ("is_admin", False),
        ("is_owner", False),
    ]


def test_true_or_branch_stays_one_opaque_atom() -> None:
    source = """
from fastapi import APIRouter

router = APIRouter()

@router.post("/chat")
def chat(is_admin: bool, is_owner: bool):
    if is_admin or is_owner:
        protected_call()
""".strip()

    call = _call(source, "protected_call")

    assert _condition_pairs(call) == [
        ("is_admin or is_owner", True),
    ]


def test_predicate_calls_execute_under_outer_conditions_only() -> None:
    source = """
from fastapi import APIRouter

router = APIRouter()

@router.post("/chat")
def chat(enabled: bool):
    if enabled and check_access():
        protected_call()
""".strip()

    predicate_call = _call(source, "check_access")
    protected_call = _call(source, "protected_call")

    assert predicate_call.lexical_conditions == ()
    assert _condition_pairs(protected_call) == [
        ("enabled", True),
        ("check_access()", True),
    ]


def _profile() -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects={"protected_call": "workspace.read"},
        sink_identity_args={"protected_call": 0},
        dependency_guard_resources={
            "require_workspace_member": "workspace_id"
        },
        dependency_guard_effects={
            "require_workspace_member": ("workspace.read",)
        },
        principal_parameter="user",
    )


def _conditional_source() -> str:
    return """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/workspaces/{workspace_id}")
def read_workspace(
    workspace_id: str,
    enabled: bool,
    user=Depends(require_workspace_member),
):
    if enabled:
        protected_call(workspace_id)
""".strip()


def test_lexical_condition_reaches_ir_without_upgrading_partial_coverage() -> None:
    source = _conditional_source()
    materials = AuthMaterials(
        head_files={"routes.py": source},
        repo="example/lexical-path-conditions",
        head_revision="head",
    )

    ir = FastApiDependencyEffectExtractor().compile(
        materials,
        _profile(),
    )
    evaluations = evaluate_protected_effect_integrity(ir)

    assert len(ir.conditions) == 1
    condition = ir.conditions[0]
    assert condition.expression == "enabled"

    assert len(ir.protected_effects) == 1
    assert ir.protected_effects[0].condition_ids == [
        condition.condition_id
    ]

    assert len(ir.paths) == 1
    path = ir.paths[0]
    assert path.condition_ids == [condition.condition_id]
    assert path.coverage_status == "partial"
    assert any(
        "control_flow_before_protected_effect" in item
        for item in path.unsupported_constructs
    )

    assert len(evaluations) == 1
    assert evaluations[0].status == "unknown"
    assert evaluations[0].extraction_coverage == "partial"


def test_semantic_summary_cache_preserves_lexical_conditions(
    tmp_path: Path,
) -> None:
    source = _conditional_source()
    materials = AuthMaterials(
        head_files={"routes.py": source},
        repo="example/lexical-summary-cache",
        head_revision="head",
    )
    root = tmp_path / "summaries"

    first = load_persistent_semantic_summaries(
        materials,
        cache=PersistentPythonSemanticSummaryCache(root),
    )
    second = load_persistent_semantic_summaries(
        materials,
        cache=PersistentPythonSemanticSummaryCache(root),
    )

    assert first.stats.misses == 1
    assert second.stats.hits == 1
    assert second.stats.parse_count == 0

    handler = second.route_summary_index.summaries[
        "routes.py"
    ].handlers[0]
    sink = next(
        call
        for call in handler.calls
        if call.leaf_name == "protected_call"
    )
    assert _condition_pairs(sink) == [("enabled", True)]


def test_persistent_fastapi_state_preserves_bound_conditions(
    tmp_path: Path,
) -> None:
    source = _conditional_source()
    materials = AuthMaterials(
        base_files={"routes.py": source},
        head_files={"routes.py": source},
        repo="example/lexical-state-cache",
        base_revision="base",
        head_revision="head",
    )
    summary_root = tmp_path / "summaries"
    state_root = tmp_path / "state"

    first = compile_persistent_incremental_fastapi_assurance(
        materials,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )
    second = compile_persistent_incremental_fastapi_assurance(
        materials,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )

    assert first.compilation.ir.conditions
    assert second.previous_state_loaded is True
    assert second.semantic_summary_stats.hits == 1
    assert second.semantic_summary_stats.parse_count == 0
    assert (
        second.compilation.ir.canonical_payload()
        == first.compilation.ir.canonical_payload()
    )
    assert second.compilation.ir.conditions[0].expression == "enabled"
