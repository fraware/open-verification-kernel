"""Tests for bounded handler control-flow calculus (#121)."""

from __future__ import annotations

from ovk.compilers.authorization.fastapi_route_summary import summarize_route_file
from ovk.compilers.authorization.handler_control_flow import (
    build_handler_control_flow_from_source,
    control_flow_from_payload,
    coverage_authoritative_for,
    dominates,
    find_nodes_by_expression_substring,
    paths_avoiding,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.persistent_fastapi_state import (
    compile_persistent_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.semantic_summary_cache import (
    PersistentPythonSemanticSummaryCache,
)


def _node(cfg, needle: str):
    matches = find_nodes_by_expression_substring(cfg, needle)
    assert matches, f"no CFG node containing {needle!r}"
    return matches[0]


def test_guard_before_sink_dominates() -> None:
    cfg = build_handler_control_flow_from_source(
        """
def handler(user):
    require_access(user)
    return sink(user)
""".strip()
    )
    guard = _node(cfg, "require_access")
    sink = _node(cfg, "sink")
    assert dominates(cfg, guard.node_id, sink.node_id)
    assert coverage_authoritative_for(cfg, sink.node_id)
    assert cfg.coverage_status == "complete"


def test_guard_only_in_true_branch_does_not_dominate() -> None:
    cfg = build_handler_control_flow_from_source(
        """
def handler(user, flag):
    if flag:
        require_access(user)
    return sink(user)
""".strip()
    )
    guard = _node(cfg, "require_access")
    sink = _node(cfg, "sink")
    assert not dominates(cfg, guard.node_id, sink.node_id)
    avoiding = paths_avoiding(cfg, cfg.entry_id, sink.node_id, guard.node_id)
    assert avoiding


def test_guard_in_both_branches_covers_sink_paths() -> None:
    cfg = build_handler_control_flow_from_source(
        """
def handler(user, flag):
    if flag:
        require_access(user)
    else:
        require_access(user)
    return sink(user)
""".strip()
    )
    guards = find_nodes_by_expression_substring(cfg, "require_access")
    sink = _node(cfg, "sink")
    assert len(guards) == 2
    assert not dominates(cfg, guards[0].node_id, sink.node_id)
    assert not dominates(cfg, guards[1].node_id, sink.node_id)

    succs = cfg.successors()
    guard_ids = {guard.node_id for guard in guards}

    def every_path_hits_guard(current: str, seen: frozenset[str], hit: bool) -> bool:
        if current in seen:
            return True
        next_seen = seen | {current}
        next_hit = hit or current in guard_ids
        if current == sink.node_id:
            return next_hit
        outs = succs.get(current, ())
        if not outs:
            return True
        return all(
            every_path_hits_guard(edge.target_id, next_seen, next_hit)
            for edge in outs
        )

    assert every_path_hits_guard(cfg.entry_id, frozenset(), False)


def test_raise_on_bypass_does_not_reach_sink() -> None:
    cfg = build_handler_control_flow_from_source(
        """
def handler(user, ok):
    if not ok:
        raise PermissionError("denied")
    return sink(user)
""".strip()
    )
    raised = _node(cfg, "PermissionError")
    sink = _node(cfg, "sink")
    avoiding = paths_avoiding(cfg, cfg.entry_id, sink.node_id, raised.node_id)
    assert avoiding
    # No path from raise to sink.
    assert not any(
        raised.node_id in path and sink.node_id in path
        for path in paths_avoiding(cfg, cfg.entry_id, sink.node_id, "__none__")
    )
    # Raise is not on any sink-reaching path that matters for bypass.
    from ovk.compilers.authorization.handler_control_flow import _nodes_reaching

    assert raised.node_id not in _nodes_reaching(cfg, sink.node_id)


def test_return_on_bypass_does_not_reach_sink() -> None:
    cfg = build_handler_control_flow_from_source(
        """
def handler(user, ok):
    if not ok:
        return None
    return sink(user)
""".strip()
    )
    early = [
        node
        for node in cfg.nodes
        if node.kind == "return" and node.expression == "return None"
    ]
    assert early
    sink = _node(cfg, "sink")
    from ovk.compilers.authorization.handler_control_flow import _nodes_reaching

    assert early[0].node_id not in _nodes_reaching(cfg, sink.node_id)


def test_nested_if_path_structure() -> None:
    cfg = build_handler_control_flow_from_source(
        """
def handler(a, b, user):
    if a:
        if b:
            require_access(user)
            return sink(user)
        return None
    return None
""".strip()
    )
    guard = _node(cfg, "require_access")
    sink = _node(cfg, "sink")
    assert dominates(cfg, guard.node_id, sink.node_id)
    assert cfg.coverage_status == "complete"
    assert any(node.kind == "branch" for node in cfg.nodes)


def test_unsupported_loop_before_sink_is_partial() -> None:
    cfg = build_handler_control_flow_from_source(
        """
def handler(items, user):
    for item in items:
        require_access(item)
    return sink(user)
""".strip()
    )
    sink = _node(cfg, "sink")
    assert cfg.coverage_status == "partial"
    assert "for" in cfg.unsupported_constructs
    assert not coverage_authoritative_for(cfg, sink.node_id)


def test_unsupported_try_before_sink_is_partial() -> None:
    cfg = build_handler_control_flow_from_source(
        """
def handler(user):
    try:
        require_access(user)
    except Exception:
        pass
    return sink(user)
""".strip()
    )
    sink = _node(cfg, "sink")
    assert cfg.coverage_status == "partial"
    assert "try" in cfg.unsupported_constructs
    assert not coverage_authoritative_for(cfg, sink.node_id)


def test_unsupported_after_terminal_does_not_contaminate_sink() -> None:
    cfg = build_handler_control_flow_from_source(
        """
def handler(user):
    require_access(user)
    return sink(user)
    for item in []:
        pass
""".strip()
    )
    guard = _node(cfg, "require_access")
    sink = _node(cfg, "sink")
    assert dominates(cfg, guard.node_id, sink.node_id)
    # Unreachable loop is not wired; coverage for the sink region stays complete.
    assert coverage_authoritative_for(cfg, sink.node_id)
    assert "for" not in cfg.unsupported_constructs


def test_unreachable_after_raise_excluded_from_sink_paths() -> None:
    cfg = build_handler_control_flow_from_source(
        """
def handler(user):
    raise RuntimeError("stop")
    return sink(user)
""".strip()
    )
    sinks = find_nodes_by_expression_substring(cfg, "sink")
    assert sinks == ()


def test_boolean_short_circuit_expands_atoms() -> None:
    """Flat ``and``/``or`` expand into per-atom branches, not one opaque BoolOp."""

    from ovk.compilers.authorization.handler_control_flow import (
        is_unconditionally_executed,
    )

    cfg = build_handler_control_flow_from_source(
        """
def handler(user):
    if require_access(user) and other(user):
        return sink(user)
    return None
""".strip()
    )
    branch_exprs = [
        node.expression
        for node in cfg.nodes
        if node.kind == "branch" and node.expression
    ]
    assert "require_access(user)" in branch_exprs
    assert "other(user)" in branch_exprs
    assert not any(
        expr is not None and " and " in expr for expr in branch_exprs
    )
    # No unconditional statement that always executes require_access.
    other_nodes = [
        node
        for node in cfg.nodes
        if node.expression == "other(user)"
    ]
    assert other_nodes
    assert is_unconditionally_executed(cfg, other_nodes[0].node_id) is False


def test_control_flow_round_trip_payload() -> None:
    cfg = build_handler_control_flow_from_source(
        """
def handler(flag, user):
    if flag:
        require_access(user)
    return sink(user)
""".strip()
    )
    restored = control_flow_from_payload(cfg.canonical_payload())
    assert restored.canonical_payload() == cfg.canonical_payload()
    assert restored.digest() == cfg.digest()


def test_route_summary_embeds_control_flow() -> None:
    import ast

    from ovk.core.bundle import content_digest

    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/items/{item_id}")
async def get_item(item_id: str, flag: bool):
    if flag:
        require_access(item_id)
    return sink(item_id)
""".strip()
    summary = summarize_route_file(
        path="routes.py",
        tree=ast.parse(source),
        source_digest=content_digest(source),
    )
    assert len(summary.handlers) == 1
    handler = summary.handlers[0]
    assert handler.control_flow is not None
    assert handler.control_flow.coverage_status == "complete"
    assert handler.origin.extractor_version == "0.16.0"


def test_branch_structure_change_invalidates_cfg_digest() -> None:
    left = """
def handler(flag, user):
    if flag:
        require_access(user)
    return sink(user)
""".strip()
    right = """
def handler(flag, user):
    if flag:
        require_access(user)
    else:
        require_access(user)
    return sink(user)
""".strip()
    left_cfg = build_handler_control_flow_from_source(left)
    right_cfg = build_handler_control_flow_from_source(right)
    assert left_cfg.digest() != right_cfg.digest()


def test_persistent_round_trip_preserves_control_flow(tmp_path) -> None:
    from ovk.compilers.authorization.semantic_summary_cache import (
        load_persistent_semantic_summaries,
    )

    files = {
        "routes.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}")
async def get_workspace(
    workspace_id: str,
    user = Depends(require_workspace_member),
):
    if workspace_id:
        return sink(workspace_id)
    return None
""".strip()
    }
    materials = AuthMaterials(
        base_files=dict(files),
        head_files=files,
        repo="example/cfg",
        base_revision="base",
        head_revision="head-1",
    )
    cache = PersistentPythonSemanticSummaryCache(tmp_path / "summaries")
    first = load_persistent_semantic_summaries(materials, cache=cache)
    handler = next(iter(first.route_summary_index.summaries.values())).handlers[0]
    assert handler.control_flow is not None
    digest = handler.control_flow.digest()

    second = load_persistent_semantic_summaries(materials, cache=cache)
    handler2 = next(iter(second.route_summary_index.summaries.values())).handlers[0]
    assert handler2.control_flow is not None
    assert handler2.control_flow.digest() == digest
    assert second.stats.hits >= 1


def test_incremental_ir_canonical_payload_unchanged_by_cfg_alone(tmp_path) -> None:
    """CFG lives in summaries/cache only; AssuranceIR identity must not change."""

    from ovk.compilers.authorization.persistent_fastapi_state import (
        PersistentFastApiIncrementalStateCache,
    )

    files = {
        "routes.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentFacade()
    return await svc.get(agent_id, workspace_id=workspace_id)
""".strip(),
        "repo.py": """
class AgentRepository:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip(),
        "service.py": """
class AgentService:
    def __init__(self):
        self._repo = AgentRepository()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._repo.get(agent_id, workspace_id=workspace_id)
""".strip(),
        "facade.py": """
class AgentFacade:
    def __init__(self):
        self._service = AgentService()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._service.get(agent_id, workspace_id=workspace_id)
""".strip(),
    }
    profile = FastApiDependencyEffectProfile(
        sink_effects={"svc.get": "workspace.agent.read"},
        sink_identity_args={"svc.get": 0},
        sink_contracts={"svc.get": "AgentFacade.get"},
        sink_contract_scope_attributes={"svc.get": "workspace_id"},
        dependency_guard_resources={"require_workspace_member": "workspace_id"},
        dependency_guard_effects={
            "require_workspace_member": ("workspace.agent.read",),
        },
        principal_parameter="user",
    )
    materials = AuthMaterials(
        base_files=dict(files),
        head_files=files,
        repo="example/cfg-ir",
        base_revision="base",
        head_revision="head-cfg",
    )
    incremental = compile_persistent_incremental_fastapi_assurance(
        materials,
        profile,
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            tmp_path / "summaries"
        ),
        state_cache=PersistentFastApiIncrementalStateCache(tmp_path / "state"),
    )
    full = FastApiDependencyEffectExtractor().compile(materials, profile)
    assert incremental.compilation.ir.canonical_payload() == full.canonical_payload()
