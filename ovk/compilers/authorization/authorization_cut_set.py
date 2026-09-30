"""Collective authorization-node coverage over a bounded handler CFG.

A set of authorization nodes covers a protected sink exactly when every
entry-to-sink execution in the represented CFG visits at least one node in the
set. Equivalently, removing those nodes disconnects the sink from the entry.

This module proves only graph structure. It does not decide whether a node is
an effective authorization guard, whether its principal/effect/resource
bindings are valid, or whether a branch outcome carries authority. Those are
separate semantic obligations.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from ovk.compilers.authorization.guard_cfg_dominance import resolve_cfg_node_id
from ovk.compilers.authorization.handler_control_flow import (
    HandlerControlFlowSummary,
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
    """Structural result for one candidate node cut set and sink."""

    covers_all_paths: bool
    coverage_status: CutSetCoverageStatus
    cut_node_ids: tuple[str, ...]
    sink_node_id: str
    uncovered_path_node_ids: tuple[str, ...] = ()
    reason: str = ""


def _reachable_path_avoiding_nodes(
    cfg: HandlerControlFlowSummary,
    *,
    sink_node_id: str,
    avoided_node_ids: frozenset[str],
) -> tuple[str, ...] | None:
    """Return one entry-to-sink path avoiding every cut node, if one exists."""

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
    cut_node_ids: frozenset[str],
) -> AuthorizationCutSetResult:
    """Evaluate whether candidate authorization nodes cover every sink path.

    A positive result is emitted only under complete sink-local CFG coverage.
    Unknown node identifiers, an empty cut set, or attempts to use the entry
    or sink itself as an authorization node are refused. The covers_all_paths
    field is structural only; authorization meaning is outside this primitive.
    """

    known = {node.node_id for node in cfg.nodes}
    ordered_cut = tuple(sorted(cut_node_ids))

    if sink_node_id not in known:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="unknown",
            cut_node_ids=ordered_cut,
            sink_node_id=sink_node_id,
            reason="sink_node_absent_from_cfg",
        )

    unknown_cut = sorted(cut_node_ids - known)
    if unknown_cut:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="unknown",
            cut_node_ids=ordered_cut,
            sink_node_id=sink_node_id,
            reason="cut_node_absent_from_cfg:" + ",".join(unknown_cut),
        )

    if cfg.entry_id in cut_node_ids:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="unknown",
            cut_node_ids=ordered_cut,
            sink_node_id=sink_node_id,
            reason="entry_node_cannot_be_authorization_cut",
        )

    if sink_node_id in cut_node_ids:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="unknown",
            cut_node_ids=ordered_cut,
            sink_node_id=sink_node_id,
            reason="sink_node_cannot_be_authorization_cut",
        )

    baseline_path = _reachable_path_avoiding_nodes(
        cfg,
        sink_node_id=sink_node_id,
        avoided_node_ids=frozenset(),
    )
    if baseline_path is None:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="unknown",
            cut_node_ids=ordered_cut,
            sink_node_id=sink_node_id,
            reason="sink_unreachable_from_entry",
        )

    if not coverage_authoritative_for(cfg, sink_node_id):
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="partial",
            cut_node_ids=ordered_cut,
            sink_node_id=sink_node_id,
            uncovered_path_node_ids=baseline_path,
            reason="sink_reaching_cfg_coverage_partial",
        )

    if not cut_node_ids:
        return AuthorizationCutSetResult(
            covers_all_paths=False,
            coverage_status="complete",
            cut_node_ids=(),
            sink_node_id=sink_node_id,
            uncovered_path_node_ids=baseline_path,
            reason="empty_authorization_cut_set",
        )

    uncovered = _reachable_path_avoiding_nodes(
        cfg,
        sink_node_id=sink_node_id,
        avoided_node_ids=cut_node_ids,
    )
    if uncovered is None:
        return AuthorizationCutSetResult(
            covers_all_paths=True,
            coverage_status="complete",
            cut_node_ids=ordered_cut,
            sink_node_id=sink_node_id,
            reason="authorization_nodes_disconnect_entry_from_sink",
        )

    return AuthorizationCutSetResult(
        covers_all_paths=False,
        coverage_status="complete",
        cut_node_ids=ordered_cut,
        sink_node_id=sink_node_id,
        uncovered_path_node_ids=uncovered,
        reason="entry_to_sink_path_avoids_all_authorization_nodes",
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
    resolved: dict[str, str] = {}
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
            resolved[guard.guard_id] = node_id

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
            guard_ids=sorted(resolved),
            guard_cfg_node_ids=dict(sorted(resolved.items())),
            unresolved_guard_ids=sorted(unresolved),
            entry_cfg_node_id=cfg.entry_id,
            effect_cfg_node_id=effect_node,
            control_flow_summary_digest=cfg.digest(),
            covers_all_paths=False,
            coverage_status="unknown",
            reason="authorization_cut_candidate_binding_unresolved",
            origin=origin,
        )

    result = evaluate_authorization_cut_set(
        cfg,
        sink_node_id=effect_node,
        cut_node_ids=frozenset(resolved.values()),
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
        guard_ids=sorted(resolved),
        guard_cfg_node_ids=dict(sorted(resolved.items())),
        entry_cfg_node_id=cfg.entry_id,
        effect_cfg_node_id=effect_node,
        control_flow_summary_digest=cfg.digest(),
        covers_all_paths=result.covers_all_paths,
        coverage_status=result.coverage_status,
        uncovered_path_node_ids=uncovered,
        reason=result.reason,
        origin=origin,
    )
