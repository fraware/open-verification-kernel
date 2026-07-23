"""Evidence v2 schema, invariant, rendering, and attestation binding tests."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.core.attestation import bundle_to_statement
from ovk.core.attestation_binding import verify_bundle_statement_binding
from ovk.core.bundle import make_bundle
from ovk.core.evidence_invariants import check_evidence_bundle_invariants
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus
from ovk.core.provenance import build_provenance_statement
from ovk.core.render import render_evidence_markdown
from ovk.core.schema_validation import load_json, validate_against_schema
from ovk.paths import schema_path


def _v2_evidence(*, executed_ok: bool = True) -> VerificationEvidence:
    executed = ["authorization-deterministic"] if executed_ok else ["rogue-backend"]
    return VerificationEvidence(
        evidence_id="ev-v2-test",
        schema_version="ovk.evidence.v2",
        subject={"repo": "example/repo", "head_sha": "abc"},
        intent={"intent_id": "no-admin-route-bypass", "title": "No admin route bypass"},
        backend_claims=[
            BackendClaim(
                backend="authorization-deterministic",
                guarantee_type="deterministic_witness",
                status=VerificationStatus.PASS,
                assumptions=["a"],
                limits=["l"],
                adapter_version="0.1.0",
            )
        ],
        decision={
            "merge_recommendation": "allow",
            "human_review_required": False,
            "aggregation_reason": "every required backend passed",
            "routing_enforced": True,
        },
        obligation_id="obl-1",
        routing_id="route-1",
        compiler={"compiler_id": "ovk.authorization.neutral.v1", "compiler_version": "0.1.0"},
        materials=[{"material_id": "m1", "sha256": "a" * 64, "uri": "ovk-material:x", "kind": "diff", "size_bytes": 1}],
        coverage={"status": "complete", "confidence": 1.0, "extracted_elements": 1},
        requested_backends=["z3-native", "authorization-deterministic"],
        eligible_backends=["authorization-deterministic"],
        selected_backends=["authorization-deterministic"],
        attempted_backends=["authorization-deterministic"],
        executed_backends=executed,
        execution_attempts=[{"attempt_id": "a1", "backend": "authorization-deterministic"}],
        aggregation_policy="ovk.aggregate.fail_dominant.v1",
        routing_enforced=True,
    )


def test_evidence_v2_schema_validation() -> None:
    schema = load_json(schema_path("verification.evidence.v2.schema.json"))
    payload = _v2_evidence().model_dump(mode="json")
    report = validate_against_schema(payload, schema)
    assert report.valid, [issue.message for issue in report.issues]


def test_bundle_v2_schema_validation() -> None:
    evidence = _v2_evidence()
    bundle = make_bundle([evidence])
    assert bundle.schema_version == "ovk.bundle.v2"
    schema = load_json(schema_path("verification.bundle.v2.schema.json"))
    report = validate_against_schema(bundle.model_dump(mode="json"), schema)
    assert report.valid, [issue.message for issue in report.issues]


def test_v1_evidence_still_loads() -> None:
    path = Path("examples/no_agent_self_approval/failing_evidence.json")
    if not path.exists():
        # Package-data layout fallback
        from ovk.paths import example_path

        path = example_path("no_agent_self_approval/failing_evidence.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    evidence = VerificationEvidence.model_validate(data)
    assert evidence.schema_version.startswith("ovk.evidence")
    assert evidence.routing_enforced is False


def test_inv_010_rejects_unselected_executed_backend() -> None:
    evidence = _v2_evidence(executed_ok=False)
    bundle = make_bundle([evidence])
    issues = check_evidence_bundle_invariants(bundle)
    assert any("OVK-INV-010" in issue.message for issue in issues)


def test_renderer_includes_control_plane_fields() -> None:
    markdown = render_evidence_markdown(_v2_evidence())
    assert "Obligation:" in markdown
    assert "Routing:" in markdown
    assert "Routing enforced:" in markdown


def test_attestation_binds_routing_ids() -> None:
    bundle = make_bundle([_v2_evidence()])
    statement = bundle_to_statement(bundle)
    assert statement["predicate"]["verification"]["evidence"][0]["routing_id"] == "route-1"
    issues = verify_bundle_statement_binding(bundle, statement)
    assert not any("OVK-INV-020" in issue.message for issue in issues)

    # Break binding
    statement["predicate"]["verification"]["evidence"][0]["routing_id"] = "other"
    issues = verify_bundle_statement_binding(bundle, statement)
    assert any("OVK-INV-020" in issue.message for issue in issues)


def test_provenance_includes_control_plane() -> None:
    bundle = make_bundle([_v2_evidence()])
    provenance = build_provenance_statement(bundle)
    assert provenance["control_plane"]["routing_ids"] == ["route-1"]
    assert provenance["bundle"]["schema_version"] == "ovk.bundle.v2"
