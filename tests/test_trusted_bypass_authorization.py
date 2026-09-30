"""Trusted bypass authorization evidence and synthetic guards (#140)."""

from __future__ import annotations

import pytest

from ovk.compilers.authorization.bypass_authority import ClosedWorldScopeProof
from ovk.compilers.authorization.handler_control_flow import (
    build_handler_control_flow_from_source,
)
from ovk.compilers.authorization.trusted_bypass_authorization import (
    evaluate_trusted_bypass_authorizations,
    read_origin_for_path,
    resolve_bypass_control_point_edge,
    synthesize_trusted_bypass_guard,
    trusted_bypass_field_name,
)
from ovk.core.assurance_ir import BypassAuthorityEvidence
from ovk.core.protected_effect_profile import ProtectedEffectProfileConfig


def _scope(*paths: str) -> ClosedWorldScopeProof:
    return ClosedWorldScopeProof(
        accounted_paths=tuple(paths),
        source_roots=(".",),
    )


def _profile_payload(**extra) -> dict:
    payload = {
        "schema_version": "ovk.protected_effect_profile.v1",
        "profile_type": "fastapi_dependency_effects_v1",
        "source_paths": ["app/**/*.py"],
        "sink_effects": {"svc.invoke": "model.invoke"},
        "dependency_guard_resources": {"require_user": "user_id"},
        "dependency_guard_effects": {"require_user": ["model.invoke"]},
        "principal_parameter": "user",
    }
    payload.update(extra)
    return payload


def test_policy_key_parses_request_state_field() -> None:
    assert trusted_bypass_field_name("request.state.bypass_filter") == "bypass_filter"
    assert trusted_bypass_field_name("bypass_filter") is None
    assert trusted_bypass_field_name("settings.allow_bypass") is None


def test_profile_trusted_bypass_authorities_round_trip() -> None:
    payload = _profile_payload(
        trusted_bypass_authorities={
            "request.state.bypass_filter": {"effects": ["model.invoke"]},
        }
    )
    config = ProtectedEffectProfileConfig.model_validate(payload)
    runtime = config.runtime_profile()
    assert runtime.trusted_bypass_authorities == {
        "request.state.bypass_filter": ("model.invoke",)
    }
    assert "trusted_bypass_authorities" in config.canonical_payload()


def test_name_alone_never_authorizes_without_profile_mapping() -> None:
    source = """
def middleware(request):
    request.state.bypass_filter = True

def handler(request):
    if request.state.bypass_filter:
        return sink()
    require_access()
    return sink()
""".strip()
    cfg = build_handler_control_flow_from_source(
        """
def handler(request):
    if request.state.bypass_filter:
        return sink()
    require_access()
    return sink()
""".strip(),
        path="app/handler.py",
        function_name="handler",
    )
    origin = read_origin_for_path("app/handler.py")
    result = evaluate_trusted_bypass_authorizations(
        files={"app/handler.py": source},
        entry_path="app/handler.py",
        function_name="handler",
        cfg=cfg,
        trusted_bypass_authorities={},
        principal_id="principal:user",
        effect_bindings={"model.invoke": ("effect:model", "resource:acted")},
        origin=origin,
        scope_proof=_scope("app/handler.py"),
    )
    assert result.evidence == ()
    assert result.guards == ()


def test_established_bypass_with_true_edge_emits_synthetic_guard() -> None:
    files = {
        "app/middleware.py": """
def attach(request):
    request.state.bypass_filter = True
""".strip(),
        "app/handler.py": """
from app.middleware import attach

def handler(request):
    if request.state.bypass_filter:
        return sink()
    require_access()
    return sink()
""".strip(),
    }
    handler_src = files["app/handler.py"]
    cfg = build_handler_control_flow_from_source(
        handler_src,
        path="app/handler.py",
        function_name="handler",
    )
    edge = resolve_bypass_control_point_edge(cfg, field_name="bypass_filter")
    assert edge is not None
    assert edge.endswith(":true")

    origin = read_origin_for_path("app/handler.py")
    result = evaluate_trusted_bypass_authorizations(
        files=files,
        entry_path="app/handler.py",
        function_name="handler",
        cfg=cfg,
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_id="principal:user",
        effect_bindings={"model.invoke": ("effect:model", "resource:acted")},
        origin=origin,
        scope_proof=_scope("app/middleware.py", "app/handler.py"),
    )
    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert evidence.status == "established"
    assert evidence.control_point_edge_id == edge
    assert evidence.writer_evidence_ids
    assert len(result.guards) == 1
    guard = result.guards[0]
    assert guard.effectiveness == "established"
    assert guard.effectiveness_evidence_ids == [evidence.evidence_id]
    assert guard.condition_ids == [edge]
    assert guard.effect_id == "effect:model"
    assert guard.resource_id == "resource:acted"


def test_client_controlled_bypass_is_violated_never_guard() -> None:
    source = """
def middleware(request, bypass_filter: bool = False):
    request.state.bypass_filter = bypass_filter

def handler(request):
    if request.state.bypass_filter:
        return sink()
    require_access()
    return sink()
""".strip()
    cfg = build_handler_control_flow_from_source(
        """
def handler(request):
    if request.state.bypass_filter:
        return sink()
    require_access()
    return sink()
""".strip(),
        path="app.py",
        function_name="handler",
    )
    origin = read_origin_for_path("app.py")
    # Externally-bound parameters are attributed on the first unit function
    # (middleware), matching closed-world writer analysis conventions.
    result = evaluate_trusted_bypass_authorizations(
        files={"app.py": source},
        entry_path="app.py",
        function_name=None,
        cfg=cfg,
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_id="principal:user",
        effect_bindings={"model.invoke": ("effect:model", "resource:acted")},
        origin=origin,
        scope_proof=_scope("app.py"),
    )
    assert result.evidence[0].status == "violated"
    assert result.guards == ()


def test_proved_writers_without_control_point_stay_unknown() -> None:
    source = """
def handler(request):
    request.state.bypass_filter = True
    return request.state.bypass_filter
""".strip()
    origin = read_origin_for_path("app.py")
    result = evaluate_trusted_bypass_authorizations(
        files={"app.py": source},
        entry_path="app.py",
        function_name="handler",
        cfg=None,
        trusted_bypass_authorities={
            "request.state.bypass_filter": ("model.invoke",),
        },
        principal_id="principal:user",
        effect_bindings={"model.invoke": ("effect:model", "resource:acted")},
        origin=origin,
        scope_proof=_scope("app.py"),
    )
    assert result.evidence[0].status == "unknown"
    assert result.evidence[0].reason == "bypass_control_point_unbound"
    assert result.guards == ()


def test_not_bypass_binds_false_outcome_edge() -> None:
    source = """
def handler(request):
    if not request.state.bypass_filter:
        require_access()
    return sink()
""".strip()
    cfg = build_handler_control_flow_from_source(source, path="h.py")
    edge = resolve_bypass_control_point_edge(cfg, field_name="bypass_filter")
    assert edge is not None
    assert edge.endswith(":false")


def test_established_evidence_requires_control_point_writers_and_scope() -> None:
    origin = read_origin_for_path("app.py", 1)
    with pytest.raises(ValueError, match="control-point edge"):
        BypassAuthorityEvidence(
            evidence_id="bypass:x",
            field_name="bypass_filter",
            read_expression="request.state.bypass_filter",
            read_origin=origin,
            status="established",
            writer_evidence_ids=["vo:1"],
            closed_world_scope_digest="scope:1",
            reason="test",
            origin=origin,
        )


def test_synthetic_guard_refuses_non_established_evidence() -> None:
    origin = read_origin_for_path("app.py", 1)
    evidence = BypassAuthorityEvidence(
        evidence_id="bypass:x",
        field_name="bypass_filter",
        read_expression="request.state.bypass_filter",
        read_origin=origin,
        status="unknown",
        control_point_edge_id="edge:branch:1->stmt:2:true",
        writer_evidence_ids=["vo:1"],
        closed_world_scope_digest="scope:1",
        reason="test",
        origin=origin,
    )
    assert (
        synthesize_trusted_bypass_guard(
            evidence=evidence,
            principal_id="principal:user",
            effect_id="effect:model",
            resource_id="resource:acted",
            origin=origin,
        )
        is None
    )


def test_empty_bypass_authority_evidence_preserves_ir_identity() -> None:
    from tests.test_assurance_ir import _ir

    ir = _ir()
    assert "bypass_authority_evidence" not in ir.canonical_payload()


def test_invalid_trusted_bypass_key_rejected() -> None:
    with pytest.raises(ValueError, match="request.state"):
        ProtectedEffectProfileConfig.model_validate(
            _profile_payload(
                trusted_bypass_authorities={
                    "bypass_filter": {"effects": ["model.invoke"]},
                }
            )
        )
