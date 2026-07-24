"""PR9 — evidence v3 and material-set binding tests."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.core.adapter_runtime import execute_obligations
from ovk.core.attestation import bundle_to_statement
from ovk.core.attestation_binding import verify_bundle_statement_binding
from ovk.core.bundle import make_bundle
from ovk.core.evidence_invariants import check_evidence_bundle_invariants
from ovk.core.materials import compute_material_set_digest
from ovk.core.provenance import build_provenance_statement
from ovk.core.schema_validation import load_json, validate_against_schema
from ovk.paths import schema_path


def _auth_policy():
    return {
        "routing": {
            "enforced_lanes": ["authorization"],
            "prefer_deterministic": True,
        },
        "budget": {"allowed_backends": ["authorization-deterministic"]},
    }


def test_compute_material_set_digest_is_order_insensitive() -> None:
    materials_a = [
        {"material_id": "b", "sha256": "2" * 64},
        {"material_id": "a", "sha256": "1" * 64},
    ]
    materials_b = list(reversed(materials_a))
    assert compute_material_set_digest(materials_a) == compute_material_set_digest(materials_b)


def test_enforced_emission_uses_evidence_v3_with_material_set_digest() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    evidence_items = execute_obligations(
        [{"lane": "authorization", "input": data, "intent_id": "no-admin-route-bypass"}],
        {},
        repo="example/repo",
        head_sha="abc",
        use_cache=False,
        policy=_auth_policy(),
        evidence_schema_version="ovk.evidence.v3",
    )
    evidence = evidence_items[0]
    assert evidence.schema_version == "ovk.evidence.v3"
    assert evidence.material_set_digest
    assert evidence.material_set_digest == compute_material_set_digest(evidence.materials)


def test_evidence_v3_schema_validation() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    evidence = execute_obligations(
        [{"lane": "authorization", "input": data, "intent_id": "no-admin-route-bypass"}],
        {},
        repo="example/repo",
        head_sha="abc",
        use_cache=False,
        policy=_auth_policy(),
        evidence_schema_version="ovk.evidence.v3",
    )[0]
    schema = load_json(schema_path("verification.evidence.v3.schema.json"))
    report = validate_against_schema(evidence.model_dump(mode="json"), schema)
    assert report.valid, [issue.message for issue in report.issues]


def test_v3_invariants_and_attestation_material_binding() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    evidence = execute_obligations(
        [{"lane": "authorization", "input": data, "intent_id": "no-admin-route-bypass"}],
        {},
        repo="example/repo",
        head_sha="abc",
        use_cache=False,
        policy=_auth_policy(),
        evidence_schema_version="ovk.evidence.v3",
    )[0]
    bundle = make_bundle([evidence])
    issues = check_evidence_bundle_invariants(bundle)
    assert not [issue for issue in issues if issue.severity == "error"]

    statement = bundle_to_statement(bundle)
    binding_issues = verify_bundle_statement_binding(bundle, statement)
    assert not binding_issues

    provenance = build_provenance_statement(bundle)
    assert evidence.material_set_digest in provenance["control_plane"]["material_set_digests"]


def test_adversarial_material_set_digest_mismatch_fails_closed() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    evidence = execute_obligations(
        [{"lane": "authorization", "input": data, "intent_id": "no-admin-route-bypass"}],
        {},
        repo="example/repo",
        head_sha="abc",
        use_cache=False,
        policy=_auth_policy(),
        evidence_schema_version="ovk.evidence.v3",
    )[0]
    tampered = evidence.model_copy(update={"material_set_digest": "deadbeef"})
    bundle = make_bundle([tampered])
    issues = check_evidence_bundle_invariants(bundle)
    assert any("material_set_digest" in issue.message for issue in issues)
