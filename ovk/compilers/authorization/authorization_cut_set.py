"""Collective authorization control-point coverage over a bounded handler CFG.

A set of control points covers a protected sink exactly when every
entry-to-sink execution in the represented CFG intersects at least one
member of the set. Control points may be statement nodes or directed CFG
edges (branch outcomes). Equivalently, removing those nodes and edges
disconnects the sink from the entry.

This module proves only graph structure. It does not decide whether a node
or edge is an effective authorization mechanism, whether principal/effect/
resource bindings are valid, or whether a particular branch outcome carries
authority. Those are separate semantic obligations.

Branch nodes themselves are never valid authorization control points:
executing a branch predicate does not authorize either outcome. Authorization
belongs on specific branch-outcome edges and/or statement nodes. When a
candidate guard binds to a branch node that has exactly one sink-reaching
outgoing outcome, that outcome edge is the structural control point.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from ovk.compilers.authorization.guard_cfg_dominance import resolve_cfg_node_id
from ovk.compilers.authorization.handler_control_flow import (
    HandlerControlFlowSummary,
    control_flow_edge_id,
    coverage_authoritative_for,
)
from ovk.core.assurance_ir import (
    AuthorizationCutSetEvidence,
    AuthorizationGuard,
    ProtectedEffect,
    SemanticOrigin,
)


CutSetCoverageStatus = Literal["complete", "partial", "unknown"]


@dataclass(frozen=True)
class AuthorizationCutSetResult:
    """Structural result for one candidate control-point cut and sink."""

    covers_all_paths: bool
    coverage_status: CutSetCoverageStatus
    cut_node_ids: tuple[str, ...]
    sink_node_id: str
    cut_edge_ids: tuple[str, ...] = ()
    uncovered_path_node_ids: tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class _ResolvedControlPoints:
    node_ids: frozenset[str]
    edge_ids: frozenset[str]
    unresolved_reason: str | None = None


def _cfg_edge_ids(cfg: HandlerControlFlowSummary) -> frozenset[str]:
    return frozenset(
        control_flow_edge_id(edge.source_id, edge.target_id, edge.branch_value)
        for edge in cfg.edges
    )


def _can_reach(
    cfg: HandlerControlFlowSummary,
    *,
    start_node_id: str,
    sink_node_id: str,
) -> bool:
    if start_node_id == sink_node_id:
        return True
    successors = cfg.successors()
    queue: deque[str] = deque([start_node_id])
    seen = {start_node_id}
    while queue:
        current = queue.popleft()
        for edge in successors.get(current, ()):
            target = edge.target_id
            if target in seen:
                continue
            if target == sink_node_id:
                return True
            seen.add(target)
            queue.append(target)
    return False


def _control_points_for_bound_node(
    cfg: HandlerControlFlowSummary,
    *,
    node_id: str,
    sink_node_id: str,
) -> _ResolvedControlPoints:
    """Map a CFG-bound candidate to node and/or edge control points.

    Statement nodes remain node cuts. Branch nodes never become node cuts:
    only a unique sink-reaching outgoing outcome may become an edge cut.
    Ambiguous multi-outcome branches refuse rather than invent authority.
    """

    node = cfg.node_map()[node_id]
    if node.kind != "branch":
        return _ResolvedControlPoints(
            node_ids=frozenset({node_id}),
            edge_ids=frozenset(),
        )

    sink_reaching = [
        edge
        for edge in cfg.successors().get(node_id, ())
        if _can_reach(cfg, start_node_id=edge.target_id, sink_node_id=sink_node_id)
    ]
    if len(sink_reaching) != 1:
        return _ResolvedControlPoints(
            node_ids=frozenset(),
            edge_ids=frozenset(),
            unresolved_reason="branch_outcome_control_point_ambiguous",
        )
    edge = sink_reaching[0]
    return _ResolvedControlPoints(
        node_ids=frozenset(),
        edge_ids=frozenset(
            {
                control_flow_edge_id(
                    edge.source_id,
                    edge.target_id,
                    edge.branch_value,
                )
            }
        ),
    )


def _reachable_path_avoiding(
    cfg: HandlerControlFlowSummary,
    *,
    sink_node_id: str,
    avoided_node_ids: frozenset[str],
    avoided_edge_ids: frozenset[str] = frozenset(),
) -> tuple[str, ...] | None:
    """Return one entry-to-sink path avoiding cut nodes and cut edges, if any."""

    if cfg.entry_id in avoided_node_ids or sink_node_id in avoided_node_ids:
        return None

    successors = cfg.successors()
    queue: deque[str] = deque([cfg.entry_id])
    predecessor: dict[str, str | None] = {cfg.entry_id: None}

    while queue:
        current = queue.popleft()
        if current == sink_node_id:
            path: list[str] = []
            cursor: str | None = current
            while cursor is not None:
                path.append(cursor)
                cursor = predecessor[cursor]
            return tuple(reversed(path))

        for edge in successors.get(current, ()):
            edge_id = control_flow_edge_id(
                edge.source_id,
                edge.target_id,
                edge.branch_value,
            )
            if edge_id in avoided_edge_ids:
                continue
            target = edge.target_id
            if target in avoided_node_ids or target in predecessor:
                continue
            predecessor[target] = current
            queue.append(target)

    return None


def evaluate_authorization_cut_set(
    cfg: HandlerControlFlowSummary,
    *,
    sink_node_id: str,
    cut_node_ids: frozenset[str] = frozenset(),
    cut_edge_ids: frozenset[str] = frozenset(),
) -> AuthorizationCutSetResult:
    """Evaluate whether candidate control points cover every sink path.

    A positive result is emitted only under complete sink-local CFG coverage.
    Unknown node or edge identifiers, an empty control-point set, attempts to
    use the entry or sink as an authorization node, or attempts to use a
    branch predicate node as an authorization node are refused. The
    covers_all_paths field is structural only; authorization meaning is
    outside this primitive.
    """

    known_nodes = {node.node_id for node in cfg.nodes}
    known_edges = _cfg_edge_ids(cfg)
    node_map = cfg.node_map()
    ordered_cut_nodes = tuple(sorted(cut_node_ids))
    ordered_cut_edges = tuple(sorted(cut_edge_ids))

    if sink_node_id not in known_nodes:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="unknown",
            cut_node_ids=ordered_cut_nodes,
            cut_edge_ids=ordered_cut_edges,
            sink_node_id=sink_node_id,
            reason="sink_node_absent_from_cfg",
        )

    unknown_cut_nodes = sorted(cut_node_ids - known_nodes)
    if unknown_cut_nodes:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="unknown",
            cut_node_ids=ordered_cut_nodes,
            cut_edge_ids=ordered_cut_edges,
            sink_node_id=sink_node_id,
            reason="cut_node_absent_from_cfg:" + ",".join(unknown_cut_nodes),
        )

    unknown_cut_edges = sorted(cut_edge_ids - known_edges)
    if unknown_cut_edges:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="unknown",
            cut_node_ids=ordered_cut_nodes,
            cut_edge_ids=ordered_cut_edges,
            sink_node_id=sink_node_id,
            reason="cut_edge_absent_from_cfg:" + ",".join(unknown_cut_edges),
        )

    if cfg.entry_id in cut_node_ids:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="unknown",
            cut_node_ids=ordered_cut_nodes,
            cut_edge_ids=ordered_cut_edges,
            sink_node_id=sink_node_id,
            reason="entry_node_cannot_be_authorization_cut",
        )

    if sink_node_id in cut_node_ids:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="unknown",
            cut_node_ids=ordered_cut_nodes,
            cut_edge_ids=ordered_cut_edges,
            sink_node_id=sink_node_id,
            reason="sink_node_cannot_be_authorization_cut",
        )

    branch_cut_nodes = sorted(
        node_id
        for node_id in cut_node_ids
        if node_map[node_id].kind == "branch"
    )
    if branch_cut_nodes:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="unknown",
            cut_node_ids=ordered_cut_nodes,
            cut_edge_ids=ordered_cut_edges,
            sink_node_id=sink_node_id,
            reason=(
                "branch_node_cannot_be_authorization_cut:"
                + ",".join(branch_cut_nodes)
            ),
        )

    baseline_path = _reachable_path_avoiding(
        cfg,
        sink_node_id=sink_node_id,
        avoided_node_ids=frozenset(),
        avoided_edge_ids=frozenset(),
    )
    if baseline_path is None:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="unknown",
            cut_node_ids=ordered_cut_nodes,
            cut_edge_ids=ordered_cut_edges,
            sink_node_id=sink_node_id,
            reason="sink_unreachable_from_entry",
        )

    if not coverage_authoritative_for(cfg, sink_node_id):
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="partial",
            cut_node_ids=ordered_cut_nodes,
            cut_edge_ids=ordered_cut_edges,
            sink_node_id=sink_node_id,
            uncovered_path_node_ids=baseline_path,
            reason="sink_reaching_cfg_coverage_partial",
        )

    if not cut_node_ids and not cut_edge_ids:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="complete",
            cut_node_ids=(),
            cut_edge_ids=(),
            sink_node_id=sink_node_id,
            uncovered_path_node_ids=baseline_path,
            reason="empty_authorization_cut_set",
        )

    uncovered = _reachable_path_avoiding(
        cfg,
        sink_node_id=sink_node_id,
        avoided_node_ids=cut_node_ids,
        avoided_edge_ids=cut_edge_ids,
    )
    if uncovered is None:
        return AuthorizationCutSetResult(
            covers_all_paths=True,
            coverage_status="complete",
            cut_node_ids=ordered_cut_nodes,
            cut_edge_ids=ordered_cut_edges,
            sink_node_id=sink_node_id,
            reason="authorization_control_points_disconnect_entry_from_sink",
        )

    return AuthorizationCutSetResult(
        covers_all_paths=False,
        coverage_status="complete",
        cut_node_ids=ordered_cut_nodes,
        cut_edge_ids=ordered_cut_edges,
        sink_node_id=sink_node_id,
        uncovered_path_node_ids=uncovered,
        reason="entry_to_sink_path_avoids_all_authorization_control_points",
    )


def build_authorization_cut_set_evidence(
    *,
    effect: ProtectedEffect,
    entrypoint: str,
    cfg: HandlerControlFlowSummary | None,
    candidate_guards: Sequence[AuthorizationGuard],
    origin: SemanticOrigin,
    allow_boolean_short_circuit_branch_guard_ids: frozenset[str] | None = None,
) -> AuthorizationCutSetEvidence | None:
    """Bind body cut candidates to structural AuthorizationCutSetEvidence.

    Returns None when there are no body cut candidates so empty collections omit
    from the canonical IR digest. Framework entrypoint dependencies must not be
    passed as candidates; they execute outside the handler CFG.
    """

    candidates = tuple(
        sorted(candidate_guards, key=lambda item: item.guard_id)
    )
    if not candidates:
        return None

    evidence_id = f"cutset:{effect.protected_effect_id}"
    allow_bool = allow_boolean_short_circuit_branch_guard_ids or frozenset()
    candidate_ids = [guard.guard_id for guard in candidates]

    if cfg is None:
        return AuthorizationCutSetEvidence(
            evidence_id=evidence_id,
            protected_effect_id=effect.protected_effect_id,
            entrypoint=entrypoint,
            unresolved_guard_ids=list(candidate_ids),
            covers_all_paths=False,
            coverage_status="unknown",
            reason="handler_cfg_absent",
            origin=origin,
        )

    effect_node = resolve_cfg_node_id(
        cfg,
        effect.origin.source_range if effect.origin else None,
    )
    bound_nodes: dict[str, str] = {}
    unresolved: list[str] = []
    for guard in candidates:
        node_id = resolve_cfg_node_id(
            cfg,
            guard.origin.source_range if guard.origin else None,
            allow_boolean_short_circuit_branch=(
                guard.guard_id in allow_bool
            ),
        )
        if node_id is None:
            unresolved.append(guard.guard_id)
        else:
            bound_nodes[guard.guard_id] = node_id

    if effect_node is None:
        return AuthorizationCutSetEvidence(
            evidence_id=evidence_id,
            protected_effect_id=effect.protected_effect_id,
            entrypoint=entrypoint,
            unresolved_guard_ids=list(candidate_ids),
            entry_cfg_node_id=cfg.entry_id,
            control_flow_summary_digest=cfg.digest(),
            covers_all_paths=False,
            coverage_status="unknown",
            reason="sink_cfg_binding_unresolved",
            origin=origin,
        )

    if unresolved:
        return AuthorizationCutSetEvidence(
            evidence_id=evidence_id,
            protected_effect_id=effect.protected_effect_id,
            entrypoint=entrypoint,
            guard_ids=sorted(bound_nodes),
            guard_cfg_node_ids=dict(sorted(bound_nodes.items())),
            unresolved_guard_ids=sorted(unresolved),
            entry_cfg_node_id=cfg.entry_id,
            effect_cfg_node_id=effect_node,
            control_flow_summary_digest=cfg.digest(),
            covers_all_paths=False,
            coverage_status="unknown",
            reason="authorization_cut_candidate_binding_unresolved",
            origin=origin,
        )

    cut_nodes: set[str] = set()
    cut_edges: set[str] = set()
    guard_node_map: dict[str, str] = {}
    outcome_unresolved: list[str] = []
    for guard_id, node_id in sorted(bound_nodes.items()):
        points = _control_points_for_bound_node(
            cfg,
            node_id=node_id,
            sink_node_id=effect_node,
        )
        if points.unresolved_reason is not None:
            outcome_unresolved.append(guard_id)
            continue
        guard_node_map[guard_id] = node_id
        cut_nodes.update(points.node_ids)
        cut_edges.update(points.edge_ids)

    if outcome_unresolved:
        return AuthorizationCutSetEvidence(
            evidence_id=evidence_id,
            protected_effect_id=effect.protected_effect_id,
            entrypoint=entrypoint,
            guard_ids=sorted(guard_node_map),
            guard_cfg_node_ids=dict(sorted(guard_node_map.items())),
            unresolved_guard_ids=sorted(outcome_unresolved),
            node_control_points=sorted(cut_nodes),
            edge_control_points=sorted(cut_edges),
            entry_cfg_node_id=cfg.entry_id,
            effect_cfg_node_id=effect_node,
            control_flow_summary_digest=cfg.digest(),
            covers_all_paths=False,
            coverage_status="unknown",
            reason="branch_outcome_control_point_ambiguous",
            origin=origin,
        )

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=effect_node,
        cut_node_ids=frozenset(cut_nodes),
        cut_edge_ids=frozenset(cut_edges),
    )
    uncovered = (
        list(result.uncovered_path_node_ids)
        if result.coverage_status == "complete" and not result.covers_all_paths
        else []
    )
    return AuthorizationCutSetEvidence(
        evidence_id=evidence_id,
        protected_effect_id=effect.protected_effect_id,
        entrypoint=entrypoint,
        guard_ids=sorted(guard_node_map),
        guard_cfg_node_ids=dict(sorted(guard_node_map.items())),
        node_control_points=sorted(cut_nodes),
        edge_control_points=sorted(cut_edges),
        entry_cfg_node_id=cfg.entry_id,
        effect_cfg_node_id=effect_node,
        control_flow_summary_digest=cfg.digest(),
        covers_all_paths=result.covers_all_paths,
        coverage_status=result.coverage_status,
        uncovered_path_node_ids=uncovered,
        reason=result.reason,
        origin=origin,
    )
