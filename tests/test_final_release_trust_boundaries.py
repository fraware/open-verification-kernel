from __future__ import annotations

import pytest

from ovk.compilers.deployment.deployment_state import compile_deployment_state
from ovk.core.metadata_provenance import (
    ProtectedMetadataArtifact,
    ProtectedSubject,
    acquisition_is_trusted,
    flatten_protected_artifact_for_loader,
    sign_protected_artifact,
)
from ovk.core.routing_pipeline import obligation_instance_key
from ovk.core.source_profile_evidence import ProfileSemanticEvidence


def _deployment_payload() -> dict:
    return {
        "schema_version": "ovk.deployment_state.v1",
        "system_identity": "deploy-controller",
        "environment": "production",
        "revision": "sha256:abc",
        "required_gates": ["approved"],
        "production_states": ["production"],
        "events": [
            {"to": "approved", "actor": "reviewer"},
            {"to": "production", "actor": "controller", "approvals": ["reviewer"]},
        ],
        "_ovk_acquisition": {
            "trusted": True,
            "signature_ref": "attacker-controlled-reference",
        },
    }


def test_deployment_document_cannot_self_assert_trust() -> None:
    ir = compile_deployment_state(_deployment_payload())
    assert "untrusted_deployment_state_acquisition" in ir.unsupported_constructs


def test_deployment_requires_external_authentication_result() -> None:
    ir = compile_deployment_state(_deployment_payload(), acquisition_trusted=True)
    assert "untrusted_deployment_state_acquisition" not in ir.unsupported_constructs


def test_obligation_instance_identity_is_not_intent_identity() -> None:
    first = {
        "lane": "ci_secrets",
        "intent_id": "no-secrets-in-untrusted-context",
        "job_id": "ci_secrets_0",
        "input_format": "infra",
        "input": {"path": ".github/workflows/a.yml"},
    }
    second = {
        **first,
        "job_id": "ci_secrets_1",
        "input": {"path": ".github/workflows/b.yml"},
    }
    assert obligation_instance_key(first) != obligation_instance_key(second)


def test_local_profile_evidence_cannot_emit_strict_eligibility() -> None:
    payload = ProfileSemanticEvidence(
        profile_id="authorization.fastapi.ast_v1",
        materials_trusted=True,
        coverage_complete=True,
        enforcement_test_present=True,
    ).as_dict()
    assert payload["candidate_evidence_complete"] is True
    assert payload["maturity_effect"] == "candidate_only"
    assert "strict_eligible" not in payload


def test_embedded_ed25519_key_cannot_bootstrap_metadata_trust() -> None:
    pytest.importorskip("cryptography")
    unsigned = ProtectedMetadataArtifact(
        kind="branch_protection",
        subject=ProtectedSubject(
            repository="example/repo",
            branch="main",
            head_sha="a" * 40,
            base_sha="b" * 40,
        ),
        payload={
            "before": {"required_checks": ["verify"]},
            "after": {"required_checks": ["verify"]},
        },
        collector_id="protected-collector",
        collector_version="1",
        acquisition_method="ed25519",
        collected_at="2026-08-25T00:00:00Z",
        payload_digest="pending",
    )
    signed = sign_protected_artifact(
        unsigned,
        ed25519_private_key="01" * 32,
        key_id="attacker-key",
    )
    flattened = flatten_protected_artifact_for_loader(signed.model_dump(mode="json"))

    trusted, reasons, _record = acquisition_is_trusted(
        flattened,
        repo="example/repo",
        head_sha="a" * 40,
        base_sha="b" * 40,
        verification_key=None,
        public_key=None,
    )
    assert trusted is False
    assert "metadata acquisition signature missing or invalid" in reasons

    assert signed.signature is not None
    assert signed.signature.public_key is not None
    trusted_with_external_root, reasons, _record = acquisition_is_trusted(
        flattened,
        repo="example/repo",
        head_sha="a" * 40,
        base_sha="b" * 40,
        verification_key=None,
        public_key=signed.signature.public_key,
    )
    assert trusted_with_external_root is True, reasons


def test_embedded_key_substitution_is_rejected_against_pinned_root() -> None:
    pytest.importorskip("cryptography")
    unsigned = ProtectedMetadataArtifact(
        kind="branch_protection",
        subject=ProtectedSubject(
            repository="example/repo",
            branch="main",
            head_sha="c" * 40,
        ),
        payload={"before": {}, "after": {}},
        collector_id="protected-collector",
        collector_version="1",
        acquisition_method="ed25519",
        collected_at="2026-08-25T00:00:00Z",
        payload_digest="pending",
    )
    signed = sign_protected_artifact(unsigned, ed25519_private_key="02" * 32, key_id="collector-key")
    flattened = flatten_protected_artifact_for_loader(signed.model_dump(mode="json"))
    other = sign_protected_artifact(unsigned, ed25519_private_key="03" * 32, key_id="collector-key")
    assert other.signature is not None and other.signature.public_key is not None

    trusted, _reasons, _record = acquisition_is_trusted(
        flattened,
        repo="example/repo",
        head_sha="c" * 40,
        base_sha=None,
        verification_key=None,
        public_key=other.signature.public_key,
    )
    assert trusted is False
