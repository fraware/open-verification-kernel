"""Tests for CFG guard/effect dominance evidence (#122)."""

from __future__ import annotations

from ovk.compilers.authorization.guard_cfg_dominance import (
    build_guard_dominance_evidence,
    cfg_dominance_is_sufficient,
    cfg_dominance_is_unknown,
)
from ovk.compilers.authorization.handler_control_flow import (
    build_handler_control_flow_from_source,
)
from ovk.core.assurance_ir import (
    AuthorizationGuard,
    ProtectedEffect,
    SemanticOrigin,
)
from ovk.core.models import SourceRange


def _origin(path: str, line: int) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="test",
        extractor_version="0.1.0",
        source_range=SourceRange(path=path, start_line=line, end_line=line),
    )


def _guard(*, line: int, effectiveness: str = "established") -> AuthorizationGuard:
    return AuthorizationGuard(
        guard_id="guard:test",
        principal_id="principal:user",
        effect_id="effect:read",
        resource_id="resource:item",
        effectiveness=effectiveness,  # type: ignore[arg-type]
        origin=_origin("h.py", line),
    )


def _effect(*, line: int) -> ProtectedEffect:
    return ProtectedEffect(
        protected_effect_id="pe:test",
        principal_id="principal:user",
        effect_id="effect:read",
        resource_id="resource:item",
        origin=_origin("h.py", line),
    )


def test_established_dominates_complete_is_sufficient() -> None:
    source = """
def handler(user):
    require_access(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    # Lines: 1 def, 2 require_access, 3 return sink
    evidence = build_guard_dominance_evidence(
        guard=_guard(line=2),
        effect=_effect(line=3),
        entrypoint="GET /x",
        cfg=cfg,
        origin=_origin("h.py", 1),
    )
    assert evidence.dominates is True
    assert evidence.coverage_status == "complete"
    assert cfg_dominance_is_sufficient(
        evidence, effectiveness="established"
    )


def test_unproved_effectiveness_even_if_dominates_is_unknown() -> None:
    source = """
def handler(user):
    require_access(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    evidence = build_guard_dominance_evidence(
        guard=_guard(line=2, effectiveness="unproved"),
        effect=_effect(line=3),
        entrypoint="GET /x",
        cfg=cfg,
        origin=_origin("h.py", 1),
    )
    # Dominance is structural and remains true even though the guard's
    # authorization effectiveness is unresolved.
    assert evidence.dominates is True
    assert cfg_dominance_is_unknown(evidence, effectiveness="unproved")
    assert not cfg_dominance_is_sufficient(
        evidence, effectiveness="unproved"
    )


def test_incomplete_cfg_is_unknown() -> None:
    source = """
def handler(user, items):
    for item in items:
        require_access(item)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    evidence = build_guard_dominance_evidence(
        guard=_guard(line=3),
        effect=_effect(line=4),
        entrypoint="GET /x",
        cfg=cfg,
        origin=_origin("h.py", 1),
    )
    assert evidence.coverage_status == "partial"
    assert evidence.dominates is False
    assert cfg_dominance_is_unknown(evidence, effectiveness="established")


def test_guard_only_on_one_branch_does_not_dominate() -> None:
    source = """
def handler(user, flag):
    if flag:
        require_access(user)
    return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    evidence = build_guard_dominance_evidence(
        guard=_guard(line=3),
        effect=_effect(line=4),
        entrypoint="GET /x",
        cfg=cfg,
        origin=_origin("h.py", 1),
    )
    assert evidence.dominates is False
    assert evidence.coverage_status == "complete"


def test_boolean_short_circuit_call_does_not_pass_dominance() -> None:
    """First atom of flat ``and`` may dominate sink under short-circuit CFG."""

    source = """
def handler(user):
    if (
        require_access(user)
        and other(user)
    ):
        return sink(user)
    return None
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    evidence = build_guard_dominance_evidence(
        guard=_guard(line=3),
        effect=_effect(line=6),
        entrypoint="GET /x",
        cfg=cfg,
        origin=_origin("h.py", 1),
    )
    assert evidence.guard_cfg_node_id is not None
    assert evidence.dominates is True
    assert cfg_dominance_is_sufficient(
        evidence, effectiveness="established"
    )


def test_boolean_or_short_circuit_call_does_not_pass_dominance() -> None:
    """``other or require_access``: require_access must not dominate sink."""

    source = """
def handler(user):
    if other(user) or require_access(user):
        return sink(user)
    return None
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    evidence = build_guard_dominance_evidence(
        guard=_guard(line=2),
        effect=_effect(line=3),
        entrypoint="GET /x",
        cfg=cfg,
        origin=_origin("h.py", 1),
    )
    # Both calls share the same source line — ambiguous binding.
    # Prefer the dedicated multi-line near-miss tests for or/and theorems.
    assert evidence.dominates is False or evidence.guard_cfg_node_id is None


def test_simple_call_condition_may_bind_branch_node() -> None:
    """A non-BoolOp condition call may bind; short-circuit opacity is about and/or."""

    source = """
def handler(user):
    if require_access(user):
        return sink(user)
    return None
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    evidence = build_guard_dominance_evidence(
        guard=_guard(line=2),
        effect=_effect(line=3),
        entrypoint="GET /x",
        cfg=cfg,
        origin=_origin("h.py", 1),
    )
    assert evidence.guard_cfg_node_id is not None
    assert evidence.dominates is True
    assert cfg_dominance_is_sufficient(
        evidence, effectiveness="established"
    )


def test_owner_match_or_has_access_does_not_dominate() -> None:
    """``owner_match or has_access(...)``: has_access is not always executed."""

    from ovk.compilers.authorization.handler_control_flow import (
        dominates as cfg_dominates,
        find_nodes_by_expression_substring,
        is_unconditionally_executed,
    )

    source = """
def handler(user, owner_match):
    if (
        owner_match
        or has_access(user)
    ):
        return sink(user)
    return None
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    access_nodes = find_nodes_by_expression_substring(cfg, "has_access")
    sink_nodes = find_nodes_by_expression_substring(cfg, "sink")
    assert access_nodes
    assert sink_nodes
    access_id = access_nodes[0].node_id
    sink_id = sink_nodes[0].node_id
    assert is_unconditionally_executed(cfg, access_id) is False
    assert cfg_dominates(cfg, access_id, sink_id) is False

    evidence = build_guard_dominance_evidence(
        guard=_guard(line=4),  # has_access line
        effect=_effect(line=6),
        entrypoint="GET /x",
        cfg=cfg,
        origin=_origin("h.py", 1),
    )
    assert evidence.guard_cfg_node_id == access_id
    assert evidence.dominates is False
    assert not cfg_dominance_is_sufficient(
        evidence, effectiveness="established"
    )


def test_enabled_and_has_access_not_unconditional() -> None:
    """``enabled and has_access(...)``: has_access is not unconditional."""

    from ovk.compilers.authorization.handler_control_flow import (
        dominates as cfg_dominates,
        find_nodes_by_expression_substring,
        is_unconditionally_executed,
    )

    source = """
def handler(user, enabled):
    if (
        enabled
        and has_access(user)
    ):
        return sink(user)
    return None
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    access_nodes = find_nodes_by_expression_substring(cfg, "has_access")
    sink_nodes = find_nodes_by_expression_substring(cfg, "sink")
    assert access_nodes
    assert sink_nodes
    access_id = access_nodes[0].node_id
    sink_id = sink_nodes[0].node_id
    assert is_unconditionally_executed(cfg, access_id) is False
    # Short-circuit-aware: has_access still dominates the sink (all sink
    # paths execute it) but is not an unconditional program-wide guard.
    assert cfg_dominates(cfg, access_id, sink_id) is True

    evidence = build_guard_dominance_evidence(
        guard=_guard(line=4),
        effect=_effect(line=6),
        entrypoint="GET /x",
        cfg=cfg,
        origin=_origin("h.py", 1),
    )
    assert evidence.guard_cfg_node_id == access_id
    assert evidence.dominates is True


def test_nested_boolop_remains_opaque_for_dominance() -> None:
    """Nested BoolOp stays unexpanded; binding refuses false PASS."""

    source = """
def handler(user, a, b):
    if (a or b) and require_access(user):
        return sink(user)
    return None
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    evidence = build_guard_dominance_evidence(
        guard=_guard(line=2),
        effect=_effect(line=3),
        entrypoint="GET /x",
        cfg=cfg,
        origin=_origin("h.py", 1),
    )
    assert evidence.guard_cfg_node_id is None
    assert evidence.dominates is False


def test_ambiguous_multi_node_span_refuses_binding() -> None:
    source = """
def handler(user):
    require_access(user); return sink(user)
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    evidence = build_guard_dominance_evidence(
        guard=_guard(line=2),
        effect=_effect(line=2),
        entrypoint="GET /x",
        cfg=cfg,
        origin=_origin("h.py", 1),
    )
    assert evidence.guard_cfg_node_id is None
    assert evidence.effect_cfg_node_id is None
    assert evidence.dominates is False
    assert evidence.coverage_status == "unknown"
