"""Bind authorization guards and protected effects to handler CFG dominance.

This module is security-facing: a guard satisfies a protected effect via CFG
dominance only when effectiveness is established, the CFG sink-reaching region
is complete, node binding is unambiguous, and the guard node dominates the
effect node. Anything weaker yields insufficient/unknown evidence — never PASS.
"""

from __future__ import annotations

from ovk.compilers.authorization.handler_control_flow import (
    HandlerControlFlowSummary,
    coverage_authoritative_for,
    dominates,
    find_nodes_covering_line,
)
from ovk.core.assurance_ir import (
    AuthorizationGuard,
    GuardDominanceEvidence,
    ProtectedEffect,
    SemanticOrigin,
)
from ovk.core.models import SourceRange


def resolve_cfg_node_id(
    cfg: HandlerControlFlowSummary,
    source_range: SourceRange | None,
) -> str | None:
    """Map a source range to exactly one CFG node, else None (ambiguous/missing)."""

    if source_range is None or source_range.start_line is None:
        return None
    line = int(source_range.start_line)
    matches = [
        node
        for node in find_nodes_covering_line(cfg, line)
        if node.kind in {"statement", "branch", "return", "raise"}
        and node.expression != "__cfg_join__"
        and (
            node.source_range is None
            or source_range.path is None
            or node.source_range.path == source_range.path
        )
    ]
    if len(matches) != 1:
        return None
    return matches[0].node_id


def build_guard_dominance_evidence(
    *,
    guard: AuthorizationGuard,
    effect: ProtectedEffect,
    entrypoint: str,
    cfg: HandlerControlFlowSummary | None,
    origin: SemanticOrigin,
) -> GuardDominanceEvidence:
    """Construct dominance evidence for one guard/effect pair.

    Never reports dominates=True unless effectiveness is established, CFG
    coverage for the sink is complete, and the guard node dominates the effect.
    """

    evidence_id = (
        f"gdom:{guard.guard_id}:{effect.protected_effect_id}"
    )
    if cfg is None:
        return GuardDominanceEvidence(
            evidence_id=evidence_id,
            guard_id=guard.guard_id,
            protected_effect_id=effect.protected_effect_id,
            entrypoint=entrypoint,
            dominates=False,
            coverage_status="unknown",
            origin=origin,
        )

    guard_node = resolve_cfg_node_id(
        cfg,
        guard.origin.source_range if guard.origin else None,
    )
    effect_node = resolve_cfg_node_id(
        cfg,
        effect.origin.source_range if effect.origin else None,
    )
    coverage: str
    if effect_node is None:
        coverage = "unknown"
        dominates_flag = False
    elif not coverage_authoritative_for(cfg, effect_node):
        coverage = "partial"
        dominates_flag = False
    else:
        coverage = "complete"
        dominates_flag = False
        if (
            guard.effectiveness == "established"
            and guard_node is not None
            and dominates(cfg, guard_node, effect_node)
        ):
            dominates_flag = True

    return GuardDominanceEvidence(
        evidence_id=evidence_id,
        guard_id=guard.guard_id,
        protected_effect_id=effect.protected_effect_id,
        entrypoint=entrypoint,
        guard_cfg_node_id=guard_node,
        effect_cfg_node_id=effect_node,
        control_flow_summary_digest=cfg.digest(),
        dominates=dominates_flag,
        coverage_status=coverage,  # type: ignore[arg-type]
        origin=origin,
    )


def cfg_dominance_is_sufficient(
    evidence: GuardDominanceEvidence,
    *,
    effectiveness: str,
) -> bool:
    """True only when sealed CFG dominance may authorize the effect path."""

    return (
        effectiveness == "established"
        and evidence.dominates
        and evidence.coverage_status == "complete"
        and evidence.guard_cfg_node_id is not None
        and evidence.effect_cfg_node_id is not None
    )


def cfg_dominance_is_unknown(
    evidence: GuardDominanceEvidence,
    *,
    effectiveness: str,
) -> bool:
    """True when CFG dominance cannot authorize and must not PASS."""

    if effectiveness != "established":
        return True
    if evidence.coverage_status != "complete":
        return True
    if evidence.guard_cfg_node_id is None or evidence.effect_cfg_node_id is None:
        return True
    return not evidence.dominates
