"""OVK-PR3 / OVK-04 evidence integrity adversarial suite.

Covers: tampered input, tampered checker output, missing checker version,
reordered JSON field stability, duplicated finding IDs, partially written
evidence, unsupported schema version, and path-redaction collisions.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest

from ovk.core.bundle import content_digest, make_bundle
from ovk.core.evidence_integrity import (
    compute_evidence_digest,
    detect_path_redaction_collisions,
    reconstruct_controlling_decision,
    redact_path,
    seal_evidence,
    verify_evidence_digest,
)
from ovk.core.evidence_invariants import check_evidence_bundle_invariants
from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.models import BackendClaim, DecisionState, EvidenceBundle, VerificationEvidence, VerificationStatus


def _base_evidence(**overrides: Any) -> VerificationEvidence:
    payload: dict[str, Any] = {
        "evidence_id": "ev-integrity-1",
        "schema_version": "ovk.evidence.v3",
        "subject": {"repo": "example/repo", "head_sha": "abc123"},
        "intent": {"intent_id": "no-admin-route-bypass", "title": "No admin route bypass", "risk": {"severity": "high"}},
        "backend_claims": [
            BackendClaim(
                backend="authorization-deterministic",
                guarantee_type="deterministic_witness",
                status=VerificationStatus.FAIL,
                assumptions=["normalized routes are complete"],
                limits=["does not prove runtime authz"],
                adapter_version="0.1.0",
            )
        ],
        "decision": {
            "decision_state": DecisionState.BLOCK.value,
            "original_decision_state": DecisionState.BLOCK.value,
            "merge_recommendation": "block",
            "human_review_required": True,
            "controlling_finding_ids": ["ev-integrity-1:authorization-deterministic"],
            "finding_contributions": [
                {
                    "finding_id": "ev-integrity-1:authorization-deterministic",
                    "claim_status": "fail",
                    "required": True,
                    "contribution": "controlling",
                }
            ],
            "aggregation_reason": "required backend failed",
            "routing_enforced": True,
        },
        "obligation_id": "obl-1",
        "routing_id": "route-1",
        "compiler": {"compiler_id": "ovk.authorization.neutral.v1", "compiler_version": "0.1.0"},
        "materials": [
            {
                "material_id": "m1",
                "sha256": "a" * 64,
                "uri": "ovk-material:diff",
                "kind": "diff",
                "size_bytes": 12,
            }
        ],
        "material_set_digest": content_digest(
            {"materials": [{"material_id": "m1", "sha256": "a" * 64}]}
        ),
        "coverage": {"status": "complete", "confidence": 1.0, "extracted_elements": 1},
        "requested_backends": ["authorization-deterministic"],
        "eligible_backends": ["authorization-deterministic"],
        "selected_backends": ["authorization-deterministic"],
        "attempted_backends": ["authorization-deterministic"],
        "executed_backends": ["authorization-deterministic"],
        "execution_attempts": [
            {
                "attempt_id": "a1",
                "backend": "authorization-deterministic",
                "started_at": "2026-07-25T16:00:00Z",
                "finished_at": "2026-07-25T16:00:01Z",
                "exit_code": 1,
                "stderr_digest": "b" * 64,
            }
        ],
        "aggregation_policy": "ovk.aggregate.fail_dominant.v1",
        "routing_enforced": True,
        "generated_artifacts": [
            {
                "kind": "control_plane_trace",
                "routing_id": "route-1",
                "material_set_digest": content_digest(
                    {"materials": [{"material_id": "m1", "sha256": "a" * 64}]}
                ),
            },
            {"kind": "input_digest", "digest": "c" * 64, "lane": "authorization"},
        ],
    }
    payload.update(overrides)
    evidence = VerificationEvidence.model_validate(payload)
    # Keep material_set_digest consistent with materials when not overridden.
    if "material_set_digest" not in overrides and evidence.materials:
        from ovk.core.materials import compute_material_set_digest

        evidence = evidence.model_copy(
            update={"material_set_digest": compute_material_set_digest(evidence.materials)}
        )
        # Keep control_plane_trace aligned.
        artifacts = []
        for artifact in evidence.generated_artifacts:
            if artifact.get("kind") == "control_plane_trace":
                artifacts.append({**artifact, "material_set_digest": evidence.material_set_digest})
            else:
                artifacts.append(artifact)
        evidence = evidence.model_copy(update={"generated_artifacts": artifacts})
    return evidence


def _sealed(**overrides: Any) -> VerificationEvidence:
    return seal_evidence(_base_evidence(**overrides))


def _error_messages(bundle: EvidenceBundle) -> list[str]:
    return [issue.message for issue in check_evidence_bundle_invariants(bundle) if issue.severity == "error"]


def test_sealed_evidence_passes_quality_and_reconstructs_decision() -> None:
    evidence = _sealed()
    assert evidence.evidence_digest
    assert evidence.checker_id == "authorization-deterministic"
    assert evidence.checker_version == "0.1.0"
    assert verify_evidence_digest(evidence)

    reconstructed = reconstruct_controlling_decision(evidence)
    assert reconstructed["digest_valid"] is True
    assert reconstructed["decision_state"] == DecisionState.BLOCK.value
    assert reconstructed["controlling_finding_ids"] == ["ev-integrity-1:authorization-deterministic"]

    bundle = make_bundle([evidence])
    report = build_evidence_quality_report(bundle)
    assert report.passed, [issue.message for issue in report.issues]


def test_tampered_input_is_rejected() -> None:
    evidence = _sealed()
    materials = deepcopy(evidence.materials or [])
    materials[0] = {**materials[0], "sha256": "d" * 64}
    tampered = evidence.model_copy(update={"materials": materials})
    # Stale input_digest + stale evidence_digest relative to new materials.
    bundle = make_bundle([tampered])
    messages = _error_messages(bundle)
    assert any("tampered input" in message or "input_digest" in message for message in messages)
    assert any("evidence_digest" in message for message in messages)
    assert build_evidence_quality_report(bundle).passed is False


def test_tampered_checker_output_is_rejected() -> None:
    evidence = _sealed()
    claims = [
        claim.model_copy(update={"status": VerificationStatus.PASS}) for claim in evidence.backend_claims
    ]
    decision = {
        **evidence.decision,
        "decision_state": DecisionState.ALLOW.value,
        "original_decision_state": DecisionState.ALLOW.value,
        "merge_recommendation": "allow",
        "human_review_required": False,
        "controlling_finding_ids": [],
    }
    tampered = evidence.model_copy(update={"backend_claims": claims, "decision": decision})
    assert verify_evidence_digest(tampered) is False
    bundle = make_bundle([tampered])
    messages = _error_messages(bundle)
    assert any("tampered checker output" in message or "evidence_digest" in message for message in messages)
    reconstructed = reconstruct_controlling_decision(tampered)
    assert reconstructed["digest_valid"] is False


def test_missing_checker_version_is_rejected() -> None:
    evidence = _sealed()
    tampered = evidence.model_copy(update={"checker_version": None})
    # Clearing version also invalidates digest; both must be rejected.
    bundle = make_bundle([tampered])
    messages = _error_messages(bundle)
    assert any("checker_version" in message for message in messages)


def test_reordered_json_fields_digest_stable() -> None:
    evidence = _sealed()
    payload = evidence.model_dump(mode="json")
    # Re-serialize with opposite key insertion order.
    reordered = json.loads(json.dumps(payload, sort_keys=False))
    # Force a different key order by rebuilding dict from reversed items.
    reordered = {key: reordered[key] for key in reversed(list(reordered.keys()))}
    assert compute_evidence_digest(payload) == compute_evidence_digest(reordered)
    assert compute_evidence_digest(reordered) == evidence.evidence_digest
    assert verify_evidence_digest(reordered)


def test_duplicated_finding_ids_are_rejected() -> None:
    evidence = _sealed()
    decision = deepcopy(evidence.decision)
    decision["controlling_finding_ids"] = [
        "ev-integrity-1:authorization-deterministic",
        "ev-integrity-1:authorization-deterministic",
    ]
    # Reseal would be honest; we inject duplicates into a sealed record to simulate tamper.
    tampered = evidence.model_copy(update={"decision": decision})
    bundle = make_bundle([tampered])
    messages = _error_messages(bundle)
    assert any("duplicated finding IDs" in message for message in messages)


def test_partially_written_evidence_is_rejected() -> None:
    evidence = _base_evidence(ovk_version="1.2.1", checker_id="authorization-deterministic")
    assert evidence.evidence_digest is None
    bundle = make_bundle([evidence])
    messages = _error_messages(bundle)
    assert any("partially written" in message for message in messages)
    assert any("evidence_digest" in message for message in messages)


def test_unsupported_schema_version_is_rejected() -> None:
    evidence = _base_evidence(schema_version="ovk.evidence.v99")
    # v99 is not sealed; unsupported schema must fail closed.
    bundle = make_bundle([evidence])
    messages = _error_messages(bundle)
    assert any("unsupported evidence schema_version" in message for message in messages)


def test_path_redaction_collisions_are_rejected() -> None:
    assert redact_path("/home/alice/proj/secret.txt") == "<home>/proj/secret.txt"
    assert redact_path("/home/bob/proj/secret.txt") == "<home>/proj/secret.txt"
    collisions = detect_path_redaction_collisions(
        ["/home/alice/proj/secret.txt", "/home/bob/proj/secret.txt"]
    )
    assert collisions

    evidence = _sealed()
    # Inject colliding redacted paths with distinct digests into sealed evidence.
    tampered = evidence.model_copy(
        update={
            "relevant_file_digests": [
                {"path": "<home>/proj/secret.txt", "sha256": "1" * 64},
                {"path": "<home>/proj/secret.txt", "sha256": "2" * 64},
            ]
        }
    )
    bundle = make_bundle([tampered])
    messages = _error_messages(bundle)
    assert any("path-redaction collisions" in message for message in messages)


def test_seal_raises_on_material_path_redaction_collision() -> None:
    evidence = _base_evidence(
        materials=[
            {
                "material_id": "m1",
                "sha256": "1" * 64,
                "path": "/home/alice/proj/secret.txt",
                "kind": "diff",
                "size_bytes": 1,
                "uri": "file:///home/alice/proj/secret.txt",
            },
            {
                "material_id": "m2",
                "sha256": "2" * 64,
                "path": "/home/bob/proj/secret.txt",
                "kind": "diff",
                "size_bytes": 1,
                "uri": "file:///home/bob/proj/secret.txt",
            },
        ]
    )
    with pytest.raises(ValueError, match="path redaction collisions"):
        seal_evidence(evidence)


def test_digest_binds_controlling_decision() -> None:
    evidence = _sealed()
    reconstructed = reconstruct_controlling_decision(evidence)
    assert reconstructed["digest_valid"] is True
    assert reconstructed["decision_state"] == evidence.decision["decision_state"]
    assert reconstructed["controlling_finding_ids"] == evidence.decision["controlling_finding_ids"]

    flipped = evidence.model_copy(
        update={
            "decision": {
                **evidence.decision,
                "decision_state": DecisionState.ALLOW.value,
                "controlling_finding_ids": [],
            }
        }
    )
    assert reconstruct_controlling_decision(flipped)["digest_valid"] is False
