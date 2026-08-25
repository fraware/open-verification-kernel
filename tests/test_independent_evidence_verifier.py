"""Independent evidence verifier and identity tamper tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from ovk.core.authoritative_runtime import execute_authoritative_plan
from ovk.core.bundle import content_digest, make_bundle
from ovk.core.evidence_integrity import compute_evidence_digest
from ovk.core.evidence_verifier import verify_bundle_semantics
from ovk.core.routing_pipeline import build_authoritative_routing_plan


def _policy() -> dict:
    return {
        "routing": {
            "mode": "shadow",
            "enforced_lanes": ["authorization"],
            "max_selected_backends": 1,
            "prefer_deterministic": True,
            "allow_fallback": False,
        },
        "budget": {
            "allowed_backends": ["authorization-deterministic"],
            "allow_network": False,
            "allow_repository_write": False,
            "max_memory_mb": 512,
        },
    }


def _bundle_dict() -> dict:
    data = json.loads(
        Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8")
    )
    obligations = [
        {
            "lane": "authorization",
            "intent_id": "no-admin-route-bypass",
            "input": data,
            "input_format": "infra",
        }
    ]
    plan = build_authoritative_routing_plan(
        obligations,
        policy=_policy(),
        repo="example/repo",
        head_sha="head",
        base_sha="base",
    )
    evidence = execute_authoritative_plan(
        obligations,
        plan,
        repo="example/repo",
        head_sha="head",
        base_sha="base",
        use_cache=False,
        parallel=False,
        policy=_policy(),
        evidence_schema_version="ovk.evidence.v3",
    )
    return make_bundle(evidence, enforce=True).model_dump(mode="json")


def _refresh_evidence_digest_and_bundle_id(payload: dict) -> None:
    evidence = payload["evidence"][0]
    evidence["signature"] = None
    evidence["evidence_digest"] = compute_evidence_digest(evidence)
    payload["bundle_id"] = "bundle-" + content_digest(
        {"subject": payload["subject"], "evidence": payload["evidence"]}
    )[:16]


def _messages(payload: dict) -> str:
    report = verify_bundle_semantics(payload)
    return "\n".join(item.message for item in report.issues)


def test_reconstructable_bundle_verifies_and_emits_bundle_v3() -> None:
    payload = _bundle_dict()
    assert payload["schema_version"] == "ovk.bundle.v3"
    report = verify_bundle_semantics(payload)
    assert report.valid, report.to_dict()


def test_tampered_obligation_is_rejected_even_after_resealing_outer_digest() -> None:
    payload = _bundle_dict()
    tampered = copy.deepcopy(payload)
    trace = next(
        row for row in tampered["evidence"][0]["generated_artifacts"]
        if row.get("kind") == "control_plane_trace" and row.get("schema_version") == "ovk.control_plane_trace.v2"
    )
    trace["obligation"]["abstraction"]["input"]["routes"][0]["protected"] = False
    _refresh_evidence_digest_and_bundle_id(tampered)
    report = verify_bundle_semantics(tampered)
    assert not report.valid
    assert "obligation_id is not canonical" in _messages(tampered) or "abstraction_digest" in _messages(tampered)


def test_tampered_route_is_rejected_even_after_resealing_outer_digest() -> None:
    payload = _bundle_dict()
    tampered = copy.deepcopy(payload)
    trace = next(
        row for row in tampered["evidence"][0]["generated_artifacts"]
        if row.get("kind") == "control_plane_trace" and row.get("schema_version") == "ovk.control_plane_trace.v2"
    )
    trace["routing"]["aggregation_policy"] = "forged-policy"
    _refresh_evidence_digest_and_bundle_id(tampered)
    report = verify_bundle_semantics(tampered)
    assert not report.valid
    assert "routing_id is not canonical" in _messages(tampered)


def test_tampered_backend_payload_is_rejected() -> None:
    payload = _bundle_dict()
    tampered = copy.deepcopy(payload)
    trace = next(
        row for row in tampered["evidence"][0]["generated_artifacts"]
        if row.get("kind") == "control_plane_trace" and row.get("schema_version") == "ovk.control_plane_trace.v2"
    )
    trace["backend_obligations"][0]["payload"]["forged"] = True
    _refresh_evidence_digest_and_bundle_id(tampered)
    report = verify_bundle_semantics(tampered)
    assert not report.valid
    assert "payload_digest is not canonical" in _messages(tampered)


def test_tampered_attempt_identity_is_rejected() -> None:
    payload = _bundle_dict()
    tampered = copy.deepcopy(payload)
    evidence = tampered["evidence"][0]
    trace = next(
        row for row in evidence["generated_artifacts"]
        if row.get("kind") == "control_plane_trace" and row.get("schema_version") == "ovk.control_plane_trace.v2"
    )
    trace["execution_attempts"][0]["termination"] = "tool_error"
    evidence["execution_attempts"][0]["termination"] = "tool_error"
    _refresh_evidence_digest_and_bundle_id(tampered)
    report = verify_bundle_semantics(tampered)
    assert not report.valid
    assert "attempt_id is not canonical" in _messages(tampered)


def test_tampered_claim_is_rejected_against_normalized_result() -> None:
    payload = _bundle_dict()
    tampered = copy.deepcopy(payload)
    tampered["evidence"][0]["backend_claims"][0]["guarantee_type"] = "forged-guarantee"
    _refresh_evidence_digest_and_bundle_id(tampered)
    report = verify_bundle_semantics(tampered)
    assert not report.valid
    assert "backend claims do not match normalized execution results" in _messages(tampered)


def test_tampered_evidence_decision_is_rejected_after_digest_reseal() -> None:
    payload = _bundle_dict()
    tampered = copy.deepcopy(payload)
    evidence = tampered["evidence"][0]
    original_state = evidence["decision"]["decision_state"]
    if original_state == "allow":
        evidence["decision"]["decision_state"] = "block"
        evidence["decision"]["merge_recommendation"] = "block"
    else:
        evidence["decision"]["decision_state"] = "allow"
        evidence["decision"]["merge_recommendation"] = "allow"
    _refresh_evidence_digest_and_bundle_id(tampered)
    report = verify_bundle_semantics(tampered)
    assert not report.valid
    messages = _messages(tampered)
    assert "stored decision_state does not recompute" in messages or "stored merge_recommendation does not recompute" in messages


def test_tampered_bundle_decision_is_rejected_without_identity_change() -> None:
    payload = _bundle_dict()
    tampered = copy.deepcopy(payload)
    original_state = tampered["decision"]["decision_state"]
    if original_state == "allow":
        tampered["decision"]["decision_state"] = "block"
        tampered["decision"]["merge_recommendation"] = "block"
    else:
        tampered["decision"]["decision_state"] = "allow"
        tampered["decision"]["merge_recommendation"] = "allow"
    report = verify_bundle_semantics(tampered)
    assert not report.valid
    messages = _messages(tampered)
    assert "bundle decision_state does not recompute" in messages or "bundle merge_recommendation does not recompute" in messages


def test_observational_timing_does_not_change_attempt_id_when_trace_is_consistent() -> None:
    payload = _bundle_dict()
    changed = copy.deepcopy(payload)
    evidence = changed["evidence"][0]
    trace = next(
        row for row in evidence["generated_artifacts"]
        if row.get("kind") == "control_plane_trace" and row.get("schema_version") == "ovk.control_plane_trace.v2"
    )
    before = trace["execution_attempts"][0]["attempt_id"]
    trace["execution_attempts"][0]["duration_ms"] = 999.0
    evidence["execution_attempts"][0]["duration_ms"] = 999.0
    _refresh_evidence_digest_and_bundle_id(changed)
    report = verify_bundle_semantics(changed)
    assert report.valid, report.to_dict()
    after = trace["execution_attempts"][0]["attempt_id"]
    assert after == before
