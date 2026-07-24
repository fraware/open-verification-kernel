"""Snapshot digests and PCS profile export."""

from __future__ import annotations

import pytest

from ovk.assurance.pcs_export import snapshot_to_verifier_profile
from ovk.assurance.pcs_validate import validate_against_pin_schema
from ovk.assurance.pin import resolve_pcs_root
from ovk.assurance.snapshot import build_configuration_snapshot
from tests.assurance.support.digest_adapter import DigestPredicateAdapter

PCS_AVAILABLE = resolve_pcs_root() is not None
requires_pcs = pytest.mark.skipif(
    not PCS_AVAILABLE,
    reason="PCS pin unavailable (set OVK_PCS_CORE_PATH or sibling ../pcs-core)",
)


def test_snapshot_digest_stable_for_identical_config() -> None:
    kwargs = {
        "backend_id": "b",
        "adapter_id": "a",
        "adapter_version": "0.1.0",
        "config": {"timeout_ms": 1000, "threshold": 1},
        "environment": {"CI": "true"},
        "mechanism_class": "static_analysis",
        "created_at": "2026-07-24T12:00:00Z",
    }
    s1 = build_configuration_snapshot(**kwargs)
    s2 = build_configuration_snapshot(**kwargs)
    assert s1.config_digest == s2.config_digest
    assert s1.content_digest == s2.content_digest


def test_material_change_changes_digest() -> None:
    base = build_configuration_snapshot(
        backend_id="b",
        adapter_id="a",
        adapter_version="0.1.0",
        config={"timeout_ms": 1000, "threshold": 1},
        mechanism_class="static_analysis",
        created_at="2026-07-24T12:00:00Z",
    )
    changed = build_configuration_snapshot(
        backend_id="b",
        adapter_id="a",
        adapter_version="0.1.0",
        config={"timeout_ms": 2000, "threshold": 1},
        mechanism_class="static_analysis",
        created_at="2026-07-24T12:00:00Z",
    )
    assert base.config_digest != changed.config_digest
    assert base.content_digest != changed.content_digest


@requires_pcs
def test_adapter_snapshot_exports_valid_pcs_profile() -> None:
    adapter = DigestPredicateAdapter(expected_digest="sha256:" + ("ab" * 32))
    snapshot = adapter.snapshot_config({"timeout_ms": 2500, "threshold": 1})
    profile = snapshot_to_verifier_profile(snapshot)
    assert profile["artifact_type"] == "VerifierProfile.v1"
    assert profile["verifier_profile_id"]
    assert profile["configuration"]["config_digest"].startswith("sha256:")
    assert profile["configuration"]["policy_digest"] is None or isinstance(
        profile["configuration"]["policy_digest"], str
    )
    # Explicit null slots present
    for key in ("policy_digest", "model_digest", "prompt_digest", "resource_limit_digest"):
        assert key in profile["configuration"]
    assert "integrity" in profile
    assert profile["integrity"]["canonicalization_version"] == "v1"
    assert profile["source_commit"] != "0" * 40
    report = validate_against_pin_schema(profile, artifact_type="VerifierProfile.v1")
    assert report.valid, report.issues
