"""Adversarial reseal corpus: mutate trust-critical fields, reseal outer digests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from ovk.core.authoritative_runtime import execute_authoritative_plan
from ovk.core.bundle import content_digest, make_bundle
from ovk.core.evidence_integrity import compute_evidence_digest
from ovk.core.evidence_verifier import (
    V3_TRUST_CRITICAL_FIELDS,
    verify_bundle_semantics,
    verify_evidence_semantics,
    verify_serialized_artifact,
)
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
    data = json.loads(Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8"))
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


def _reseal(payload: dict) -> None:
    evidence = payload["evidence"][0]
    evidence["signature"] = None
    evidence["evidence_digest"] = compute_evidence_digest(evidence)
    payload["bundle_id"] = "bundle-" + content_digest(
        {"subject": payload["subject"], "evidence": payload["evidence"]}
    )[:16]


def _mutate(value, path: tuple):
    if not path:
        if isinstance(value, str):
            return value + "-tampered"
        if isinstance(value, bool):
            return not value
        if isinstance(value, int):
            return value + 1
        if value is None:
            return "tampered"
        if isinstance(value, list):
            return list(value) + ["tampered"]
        if isinstance(value, dict):
            updated = dict(value)
            updated["tampered"] = True
            return updated
        return "tampered"
    head, rest = path[0], path[1:]
    if isinstance(value, list) and isinstance(head, int):
        clone = list(value)
        clone[head] = _mutate(clone[head], rest)
        return clone
    clone = dict(value)
    clone[head] = _mutate(clone[head], rest)
    return clone


TRUST_CRITICAL_MUTATIONS: dict[str, tuple] = {
    "evidence_id": ("evidence_id",),
    "subject": ("subject", "head_sha"),
    "intent": ("intent", "intent_id"),
    "backend_claims": ("backend_claims", 0, "status"),
    "decision": ("decision", "decision_state"),
    "obligation_id": ("obligation_id",),
    "routing_id": ("routing_id",),
    "material_set_digest": ("material_set_digest",),
    "compiler": ("compiler", "compiler_version"),
    "materials": ("materials", 0, "sha256"),
    "coverage": ("coverage", "status"),
    "requested_backends": ("requested_backends",),
    "eligible_backends": ("eligible_backends",),
    "selected_backends": ("selected_backends",),
    "attempted_backends": ("attempted_backends",),
    "executed_backends": ("executed_backends",),
    "execution_attempts": ("execution_attempts", 0, "termination"),
    "aggregation_policy": ("aggregation_policy",),
    "routing_enforced": ("routing_enforced",),
    "evidence_digest": ("evidence_digest",),
}


def test_frozen_v3_field_set_covers_mutations() -> None:
    missing = set(TRUST_CRITICAL_MUTATIONS) - V3_TRUST_CRITICAL_FIELDS
    assert not missing


def test_every_trust_critical_field_mutation_is_rejected_after_reseal() -> None:
    original = _bundle_dict()
    assert verify_bundle_semantics(original).valid
    for name, path in TRUST_CRITICAL_MUTATIONS.items():
        tampered = copy.deepcopy(original)
        tampered["evidence"][0] = _mutate(tampered["evidence"][0], path)
        if name != "evidence_digest":
            _reseal(tampered)
        report = verify_bundle_semantics(tampered)
        assert not report.valid, f"{name} mutation was accepted after reseal"


def test_unknown_trust_critical_field_is_rejected_after_reseal() -> None:
    payload = _bundle_dict()
    payload["evidence"][0]["forged_trust_field"] = "allow"
    _reseal(payload)
    report = verify_bundle_semantics(payload)
    assert not report.valid
    assert any("unknown trust-critical field" in item.message for item in report.issues)


def test_nearly_valid_trace_returns_invalid_report_not_exception() -> None:
    payload = _bundle_dict()
    payload["evidence"][0]["generated_artifacts"] = [{"kind": "control_plane_trace", "schema_version": "ovk.control_plane_trace.v2"}]
    report = verify_evidence_semantics(payload["evidence"][0])
    assert report.valid is False
    assert report.issues


def test_verify_serialized_artifact_never_raises(tmp_path: Path) -> None:
    target = tmp_path / "hostile.json"
    target.write_text("{not json", encoding="utf-8")
    report = verify_serialized_artifact(target)
    assert report["valid"] is False
    assert report["schema_version"] == "ovk.verifier.report.v1"
    assert report["issues"]
