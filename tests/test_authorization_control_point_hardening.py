"""Hardened authorization-control-point verification (#154)."""

from __future__ import annotations

import pytest

from ovk.compilers.authorization.handler_control_flow import (
    scoped_control_flow_edge_id_from_local,
)
from ovk.core.assurance_ir import (
    AuthorizationControlPointEvidence,
    AuthorizationCutSetEvidence,
    AuthorizationGuard,
    BypassAuthorityEvidence,
    SemanticOrigin,
)
from ovk.core.models import SourceRange
from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity
from ovk.core.protected_effect_integrity import (
    _edge_control_points_independently_proved,
    compile_protected_effect_integrity,
)
from tests.test_protected_effect_integrity import _base_ir, _status


def _origin(path: str = "app.py", line: int = 1) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="test",
        extractor_version="0.1.0",
        source_range=SourceRange(path=path, start_line=line, end_line=line),
    )


def test_scoped_edge_id_must_match_cfg_entrypoint_local() -> None:
    edge_id = "edge:branch:1->stmt:2:true"
    digest = "cfg:complete"
    entry = "POST /refund"
    scoped = scoped_control_flow_edge_id_from_local(
        control_flow_summary_digest=digest,
        entrypoint=entry,
        local_edge_id=edge_id,
    )
    AuthorizationControlPointEvidence(
        evidence_id="acp:1",
        guard_id="g:bypass",
        protected_effect_id="pe:refund",
        principal_id="p:user",
        effect_id="e:refund",
        resource_id="r:authorized",
        entrypoint=entry,
        control_flow_summary_digest=digest,
        edge_id=edge_id,
        scoped_edge_id=scoped,
        bypass_evidence_id="bypass:1",
        origin=_origin(),
    )
    with pytest.raises(ValueError, match="scoped_edge_id"):
        AuthorizationControlPointEvidence(
            evidence_id="acp:bad",
            guard_id="g:bypass",
            protected_effect_id="pe:refund",
            principal_id="p:user",
            effect_id="e:refund",
            resource_id="r:authorized",
            entrypoint=entry,
            control_flow_summary_digest=digest,
            edge_id=edge_id,
            scoped_edge_id="edge:forged",
            bypass_evidence_id="bypass:1",
            origin=_origin(),
        )


def test_edge_proof_requires_exact_effect_binding_and_bypass_id() -> None:
    ir = _base_ir(
        guard_resource="r:authorized",
        effect_resource="r:authorized",
        include_binding=False,
    )
    edge_id = "edge:branch:1->stmt:sink:true"
    digest = "cfg:complete"
    entry = "POST /refund"
    scoped = scoped_control_flow_edge_id_from_local(
        control_flow_summary_digest=digest,
        entrypoint=entry,
        local_edge_id=edge_id,
    )
    ir.guards = [
        AuthorizationGuard(
            guard_id="g:bypass",
            principal_id="p:user",
            effect_id="e:refund",
            resource_id="r:authorized",
            effectiveness="established",
            effectiveness_evidence_ids=["bypass:filter"],
            condition_ids=[edge_id],
            origin=_origin(line=2),
        )
    ]
    ir.paths[0].guard_ids = ["g:bypass"]
    ir.bypass_authority_evidence = [
        BypassAuthorityEvidence(
            evidence_id="bypass:filter",
            field_name="bypass_filter",
            read_expression="request.state.bypass_filter",
            read_origin=_origin(line=2),
            status="established",
            control_point_edge_id=edge_id,
            control_flow_summary_digest=digest,
            entrypoint=entry,
            writer_evidence_ids=["vo:1"],
            closed_world_scope_digest="scope:1",
            reason="test",
            origin=_origin(line=2),
        )
    ]
    ir.authorization_control_point_evidence = [
        AuthorizationControlPointEvidence(
            evidence_id="acp:ok",
            guard_id="g:bypass",
            protected_effect_id="pe:refund",
            principal_id="p:user",
            effect_id="e:refund",
            resource_id="r:authorized",
            entrypoint=entry,
            control_flow_summary_digest=digest,
            edge_id=edge_id,
            scoped_edge_id=scoped,
            bypass_evidence_id="bypass:filter",
            origin=_origin(line=2),
        )
    ]
    ir.authorization_cut_set_evidence = [
        AuthorizationCutSetEvidence(
            evidence_id="cutset:pe:refund",
            protected_effect_id="pe:refund",
            entrypoint=entry,
            guard_ids=["g:bypass"],
            guard_cfg_node_ids={"g:bypass": "stmt:bypass"},
            node_control_points=["stmt:bypass"],
            edge_control_points=[edge_id],
            entry_cfg_node_id="entry:1",
            effect_cfg_node_id="stmt:sink",
            control_flow_summary_digest=digest,
            covers_all_paths=True,
            coverage_status="complete",
            reason="test",
            origin=_origin(),
        )
    ]
    effect = ir.protected_effects[0]
    cut = ir.authorization_cut_set_evidence[0]
    assert _edge_control_points_independently_proved(
        ir=ir, cut_evidence=cut, effect=effect
    )

    # Wrong resource on the control point refuses the edge proof.
    ir.authorization_control_point_evidence[0] = AuthorizationControlPointEvidence(
        evidence_id="acp:wrong-resource",
        guard_id="g:bypass",
        protected_effect_id="pe:refund",
        principal_id="p:user",
        effect_id="e:refund",
        resource_id="r:other",
        entrypoint=entry,
        control_flow_summary_digest=digest,
        edge_id=edge_id,
        scoped_edge_id=scoped,
        bypass_evidence_id="bypass:filter",
        origin=_origin(line=2),
    )
    assert not _edge_control_points_independently_proved(
        ir=ir, cut_evidence=cut, effect=effect
    )

    # Wrong bypass evidence id refuses even when fields otherwise match.
    ir.authorization_control_point_evidence[0] = AuthorizationControlPointEvidence(
        evidence_id="acp:wrong-bypass",
        guard_id="g:bypass",
        protected_effect_id="pe:refund",
        principal_id="p:user",
        effect_id="e:refund",
        resource_id="r:authorized",
        entrypoint=entry,
        control_flow_summary_digest=digest,
        edge_id=edge_id,
        scoped_edge_id=scoped,
        bypass_evidence_id="bypass:missing",
        origin=_origin(line=2),
    )
    assert not _edge_control_points_independently_proved(
        ir=ir, cut_evidence=cut, effect=effect
    )

    # Restore a matching control point, then mismatch bypass entrypoint.
    ir.authorization_control_point_evidence[0] = AuthorizationControlPointEvidence(
        evidence_id="acp:ok",
        guard_id="g:bypass",
        protected_effect_id="pe:refund",
        principal_id="p:user",
        effect_id="e:refund",
        resource_id="r:authorized",
        entrypoint=entry,
        control_flow_summary_digest=digest,
        edge_id=edge_id,
        scoped_edge_id=scoped,
        bypass_evidence_id="bypass:filter",
        origin=_origin(line=2),
    )
    ir.bypass_authority_evidence[0] = BypassAuthorityEvidence(
        evidence_id="bypass:filter",
        field_name="bypass_filter",
        read_expression="request.state.bypass_filter",
        read_origin=_origin(line=2),
        status="established",
        control_point_edge_id=edge_id,
        control_flow_summary_digest=digest,
        entrypoint="POST /other",
        writer_evidence_ids=["vo:1"],
        closed_world_scope_digest="scope:1",
        reason="test",
        origin=_origin(line=2),
    )
    assert not _edge_control_points_independently_proved(
        ir=ir, cut_evidence=cut, effect=effect
    )
    obligation = compile_protected_effect_integrity(ir)[0]
    evaluation = evaluate_protected_effect_integrity(ir)
    assert evaluation[0].status != "pass"
    assert _status(obligation, "guard_presence") == "violated"
