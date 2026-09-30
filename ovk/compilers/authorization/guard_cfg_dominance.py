"""Bind body-executed authorization guards to handler CFG dominance.

This module proves only the structural execution relation. Guard effectiveness
is a separate Protected Effect obligation and must not change whether the guard
node structurally dominates the protected effect. Incomplete coverage or
ambiguous node binding yields unresolved evidence and must never be repaired by
falling back to an unrelated dominance calculus.
"""

from __future__ import annotations

import ast

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


def _condition_has_boolean_short_circuit(expression: str | None) -> bool:
    """True when a branch condition is opaque under short-circuit ``and``/``or``.

    Calls nested inside Boolean operators must not be treated as unconditional
    guard execution nodes. Unparseable conditions fail closed.
    """

    if expression is None:
        return False
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return True
    return any(isinstance(node, ast.BoolOp) for node in ast.walk(tree))


def resolve_cfg_node_id(
    cfg: HandlerControlFlowSummary,
    source_range: SourceRange | None,
) -> str | None:
    """Map a source range to exactly one CFG node, else None (ambiguous/missing).

    Branch nodes whose conditions contain ``and``/``or`` are refused: binding a
    call inside a Boolean expression as an executed guard would violate
    short-circuit opacity and can produce false dominance PASS.
    """

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
        and not (
            node.kind == "branch"
            and _condition_has_boolean_short_circuit(node.expression)
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
    """Construct structural dominance evidence for one body guard/effect pair.

    The dominates field records only the CFG relation. Effectiveness remains a
    separate obligation. True dominance still requires complete sink-reaching
    CFG coverage and unambiguous node binding.
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
            guard_node is not None
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
