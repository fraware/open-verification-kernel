from pathlib import Path

import pytest

from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
from tests.native_ci import skip_unless_z3


def _provenance_backend(evidence) -> str | None:
    for artifact in evidence.generated_artifacts:
        if artifact.get("kind") == "backend_provenance":
            return str(artifact.get("backend"))
    return None


@pytest.mark.skipif(skip_unless_z3(), reason="Z3 integration runs in tier-1 workflow")
def test_z3_native_path_blocks_admin_bypass_when_z3_installed() -> None:
    payload = Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8")
    import json

    data = json.loads(payload)
    evidence = evaluate_validated_authorization_path(data, repo="test/repo", head_sha="abc12345")
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.decision.get("merge_recommendation") == "block"
    assert _provenance_backend(evidence) == "z3"


@pytest.mark.skipif(skip_unless_z3(), reason="Z3 integration runs in tier-1 workflow")
def test_z3_native_path_allows_protected_admin_route_when_z3_installed() -> None:
    payload = Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8")
    import json

    data = json.loads(payload)
    evidence = evaluate_validated_authorization_path(data, repo="test/repo", head_sha="abc12345")
    assert evidence.backend_claims[0].status.value == "pass"
    assert evidence.decision.get("merge_recommendation") == "allow"
    assert _provenance_backend(evidence) == "z3"



@pytest.mark.skipif(skip_unless_z3(), reason="Z3 integration runs in tier-1 workflow")
def test_protected_effect_evidence_binds_native_z3_checker_provenance() -> None:
    import z3

    from ovk.core.assurance_ir import (
        AssuranceCoverage,
        AssuranceExtractorIdentity,
        AssuranceIR,
        AuthorizationGuard,
        EffectRef,
        PrincipalRef,
        ProtectedEffect,
        ResourceBinding,
        ResourceRef,
        SemanticOrigin,
        SemanticPath,
    )
    from ovk.core.models import VerificationSubject
    from ovk.core.protected_effect_evaluation import evaluate_protected_effect_integrity
    from ovk.core.protected_effect_evidence import (
        build_execution_fingerprint,
        protected_effect_evaluation_to_evidence,
    )
    from ovk.core.resource_identity import ResourceIdentityTerm

    origin = SemanticOrigin(
        path="routes.py",
        extractor_id="test.native.z3",
        extractor_version="0.1.0",
    )
    ir = AssuranceIR(
        subject=VerificationSubject(
            repo="example/native-z3",
            base_sha="base",
            head_sha="head",
        ),
        extractor=AssuranceExtractorIdentity(
            extractor_id="test.native.z3",
            extractor_version="0.1.0",
        ),
        coverage=AssuranceCoverage(status="complete", confidence=1.0),
        principals=[
            PrincipalRef(
                principal_id="p:user",
                symbol="user",
                origin=origin,
            )
        ],
        resources=[
            ResourceRef(
                resource_id="r:authorized",
                symbol="workspace_id",
                identity_term=ResourceIdentityTerm.symbol("workspace_id"),
                origin=origin,
            ),
            ResourceRef(
                resource_id="r:acted",
                symbol="agent_id",
                scope_term=ResourceIdentityTerm.symbol("$scope:unknown"),
                origin=origin,
            ),
        ],
        effects=[
            EffectRef(
                effect_id="e:read",
                name="workspace.agent.read",
                origin=origin,
            )
        ],
        guards=[
            AuthorizationGuard(
                guard_id="g:read",
                principal_id="p:user",
                effect_id="e:read",
                resource_id="r:authorized",
                origin=origin,
            )
        ],
        protected_effects=[
            ProtectedEffect(
                protected_effect_id="pe:read",
                principal_id="p:user",
                effect_id="e:read",
                resource_id="r:acted",
                origin=origin,
            )
        ],
        resource_bindings=[
            ResourceBinding(
                binding_id="binding:scope",
                authorized_resource_id="r:authorized",
                acted_resource_id="r:acted",
                relation="same_tenant",
                authorized_projection="identity",
                acted_projection="scope",
                origin=origin,
            )
        ],
        paths=[
            SemanticPath(
                path_id="path:read",
                entrypoint="GET /agents/{agent_id}",
                guard_ids=["g:read"],
                protected_effect_ids=["pe:read"],
                binding_ids=["binding:scope"],
                origin=origin,
            )
        ],
    )

    evaluation = evaluate_protected_effect_integrity(ir)[0]
    assert evaluation.status == "fail"
    binding = evaluation.resource_binding_evidence[0]
    assert binding.engine == "z3"
    assert binding.tool_version == z3.get_version_string()

    fingerprint = build_execution_fingerprint(
        evaluation,
        environment_digest="env:z3-native",
        tool_digest="digest:z3-native",
        worker_image_digest="sha256:z3-worker",
        native_execution=True,
    )
    assert len(fingerprint.binding_checkers) == 1
    assert fingerprint.binding_checkers[0].engine == "z3"
    assert fingerprint.binding_checkers[0].tool_version == z3.get_version_string()

    evidence = protected_effect_evaluation_to_evidence(
        ir,
        evaluation,
        policy_digest="policy:z3-native",
        execution_fingerprint=fingerprint,
    )
    assert evidence.evidence_digest
