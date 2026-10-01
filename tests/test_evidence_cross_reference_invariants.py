"""Evidence cross-reference invariants for bypass/control-point binding (#158)."""

from __future__ import annotations

import pytest

from ovk.compilers.authorization.handler_control_flow import (
    scoped_control_flow_edge_id_from_local,
)
from ovk.core.assurance_ir import (
    AssuranceCoverage,
    AssuranceExtractorIdentity,
    AssuranceIR,
    AuthorizationControlPointEvidence,
    BypassAuthorityEvidence,
    SemanticOrigin,
)
from ovk.core.models import SourceRange, VerificationSubject


def _origin(line: int = 1) -> SemanticOrigin:
    return SemanticOrigin(
        path="app.py",
        extractor_id="test",
        extractor_version="0.1.0",
        source_range=SourceRange(path="app.py", start_line=line, end_line=line),
    )


def _subject() -> VerificationSubject:
    return VerificationSubject(repo="example/repo", head_sha="abc123")


def test_ir_rejects_control_point_with_unknown_bypass_id() -> None:
    edge = "edge:branch:1->stmt:2:true"
    digest = "cfg:complete"
    entry = "POST /refund"
    scoped = scoped_control_flow_edge_id_from_local(
        control_flow_summary_digest=digest,
        entrypoint=entry,
        local_edge_id=edge,
    )
    with pytest.raises(ValueError, match="bypass_evidence_id"):
        AssuranceIR(
            subject=_subject(),
            extractor=AssuranceExtractorIdentity(
                extractor_id="test",
                extractor_version="0.1.0",
            ),
            coverage=AssuranceCoverage(status="partial", confidence=0.5),
            bypass_authority_evidence=[
                BypassAuthorityEvidence(
                    evidence_id="bypass:filter",
                    field_name="bypass_filter",
                    read_expression="request.state.bypass_filter",
                    read_origin=_origin(),
                    status="established",
                    control_point_edge_id=edge,
                    control_flow_summary_digest=digest,
                    entrypoint=entry,
                    writer_evidence_ids=["vo:1"],
                    closed_world_scope_digest="scope:1",
                    reason="test",
                    origin=_origin(),
                )
            ],
            authorization_control_point_evidence=[
                AuthorizationControlPointEvidence(
                    evidence_id="acp:1",
                    guard_id="g:bypass",
                    protected_effect_id="pe:1",
                    principal_id="p:1",
                    effect_id="e:1",
                    resource_id="r:1",
                    entrypoint=entry,
                    control_flow_summary_digest=digest,
                    edge_id=edge,
                    scoped_edge_id=scoped,
                    bypass_evidence_id="bypass:missing",
                    origin=_origin(),
                )
            ],
        )


def test_ir_rejects_entrypoint_mismatch_between_control_point_and_bypass() -> None:
    edge = "edge:branch:1->stmt:2:true"
    digest = "cfg:complete"
    entry = "POST /refund"
    other = "POST /other"
    scoped = scoped_control_flow_edge_id_from_local(
        control_flow_summary_digest=digest,
        entrypoint=entry,
        local_edge_id=edge,
    )
    with pytest.raises(ValueError, match="entrypoint"):
        AssuranceIR(
            subject=_subject(),
            extractor=AssuranceExtractorIdentity(
                extractor_id="test",
                extractor_version="0.1.0",
            ),
            coverage=AssuranceCoverage(status="partial", confidence=0.5),
            bypass_authority_evidence=[
                BypassAuthorityEvidence(
                    evidence_id="bypass:filter",
                    field_name="bypass_filter",
                    read_expression="request.state.bypass_filter",
                    read_origin=_origin(),
                    status="established",
                    control_point_edge_id=edge,
                    control_flow_summary_digest=digest,
                    entrypoint=other,
                    writer_evidence_ids=["vo:1"],
                    closed_world_scope_digest="scope:1",
                    reason="test",
                    origin=_origin(),
                )
            ],
            authorization_control_point_evidence=[
                AuthorizationControlPointEvidence(
                    evidence_id="acp:1",
                    guard_id="g:bypass",
                    protected_effect_id="pe:1",
                    principal_id="p:1",
                    effect_id="e:1",
                    resource_id="r:1",
                    entrypoint=entry,
                    control_flow_summary_digest=digest,
                    edge_id=edge,
                    scoped_edge_id=scoped,
                    bypass_evidence_id="bypass:filter",
                    origin=_origin(),
                )
            ],
        )
