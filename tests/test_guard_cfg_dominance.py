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
    assert evidence.dominates is False
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
    """Calls inside and/or must not bind as unconditional executed guards."""

    source = """
def handler(user):
    if require_access(user) and other(user):
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
    assert not cfg_dominance_is_sufficient(
        evidence, effectiveness="established"
    )
    assert cfg_dominance_is_unknown(evidence, effectiveness="established")


def test_boolean_or_short_circuit_call_does_not_pass_dominance() -> None:
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
    assert evidence.guard_cfg_node_id is None
    assert evidence.dominates is False


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
