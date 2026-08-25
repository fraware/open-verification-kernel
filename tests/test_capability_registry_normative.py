"""Tests for normative capability registry validation (OVK-02)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.core.capabilities import (
    CapabilityRegistry,
    validate_capability_manifest,
)
from ovk.core.execution_models import BackendCapabilityManifest, BackendGuaranteeDeclaration, BackendToolIdentity
from scripts.validate_capabilities import validate_capabilities


ROOT = Path(__file__).resolve().parents[1]


def _valid_manifest(**overrides: object) -> dict:
    payload = {
        "capability_id": "example-v1",
        "checker_id": "example",
        "version": "0.1.0",
        "implementation": "ovk-adapter-example",
        "input_contract": "JSON input",
        "output_contract": "ovk.result.v1",
        "claim_class": "policy_evaluation",
        "tool": {
            "name": "example",
            "adapter": "ovk-adapter-example",
            "adapter_version": "0.1.0",
        },
        "backend_class": "custom",
        "supported_domains": ["authorization"],
        "supported_property_kinds": ["safety"],
        "guarantee": {
            "type": "policy_evaluation",
            "meaning_of_pass": "pass",
            "meaning_of_fail": "fail",
            "meaning_of_unknown": "unknown",
        },
        "assumptions": ["test assumption"],
        "trusted_components": ["adapter"],
        "failure_semantics": "errors map to error",
        "timeout_semantics": "unknown",
        "unsupported_semantics": "unsupported inputs yield unknown",
        "determinism_status": "deterministic",
        "release_status": "experimental",
        "owner": "ovk-maintainers",
        "native_execution": False,
    }
    payload.update(overrides)
    return payload


def test_validate_capabilities_passes_for_repo_manifests() -> None:
    assert validate_capabilities() == []


def test_registry_loads_advertised_checkers() -> None:
    registry = CapabilityRegistry.from_directory(ROOT / "adapters")
    checkers = {m["checker_id"] for m in registry.all()}
    assert checkers == {
        "opa",
        "z3",
        "cbmc",
        "cedar",
        "tla+",
        "kani",
        "dafny",
        "verus",
        "lean",
        "alloy",
        "lane-self-protection",
        "lane-authorization",
        "lane-infrastructure",
        "lane-ci-secrets",
        "lane-deployment",
    }


def test_reject_stable_without_conformance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "ovk.core.adapter_conformance.is_fully_conformant",
        lambda *_args, **_kwargs: False,
    )
    failures = validate_capability_manifest(
        _valid_manifest(release_status="stable", native_execution=True, checker_id="opa"),
        source="test",
    )
    assert any("requires full seven-item" in item for item in failures)


def test_reject_unknown_release_status() -> None:
    failures = validate_capability_manifest(
        _valid_manifest(release_status="ga"),
        source="test",
    )
    assert any("unknown release_status" in item for item in failures)


def test_stable_allowed_when_conformant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "ovk.core.adapter_conformance.is_fully_conformant",
        lambda *_args, **_kwargs: True,
    )
    failures = validate_capability_manifest(
        _valid_manifest(release_status="stable", native_execution=True, checker_id="opa"),
        source="test",
    )
    assert not any("requires full seven-item" in item for item in failures)
    assert not any("only native-execution" in item for item in failures)


def test_non_native_cannot_claim_beyond_preview() -> None:
    # Non-native checkers cannot use stable even if conformance were claimed.
    failures = validate_capability_manifest(
        _valid_manifest(release_status="stable", native_execution=False),
        source="test",
    )
    assert any("only native-execution" in item or "requires full seven-item" in item for item in failures)


def test_typed_manifest_fills_normative_fields() -> None:
    manifest = BackendCapabilityManifest(
        capability_id="lane-test-v1",
        tool=BackendToolIdentity(
            name="lane-test",
            adapter="ovk-adapter-lane-test",
            adapter_version="0.1.0",
        ),
        backend_class="custom",
        guarantee=BackendGuaranteeDeclaration(
            type="deterministic_witness",
            meaning_of_pass="p",
            meaning_of_fail="f",
            meaning_of_unknown="u",
        ),
        supported_domains=["authorization"],
        supported_property_kinds=["access_control"],
        assumptions=["a"],
        limits=["l"],
    )
    assert manifest.checker_id == "lane-test"
    assert manifest.implementation == "ovk-adapter-lane-test"
    assert manifest.claim_class == "deterministic_witness"
    assert manifest.timeout_semantics == "unknown"
    assert manifest.release_status == "experimental"


def test_typed_manifest_rejects_unknown_release_status() -> None:
    with pytest.raises(Exception, match="release_status"):
        BackendCapabilityManifest(
            capability_id="broken-v1",
            tool=BackendToolIdentity(
                name="broken",
                adapter="ovk-adapter-broken",
                adapter_version="0.1.0",
            ),
            backend_class="custom",
            guarantee=BackendGuaranteeDeclaration(
                type="x",
                meaning_of_pass="p",
                meaning_of_fail="f",
                meaning_of_unknown="u",
            ),
            supported_domains=["authorization"],
            supported_property_kinds=["access_control"],
            release_status="not-a-status",  # type: ignore[arg-type]
        )


def test_every_capability_json_has_required_normative_fields() -> None:
    required = {
        "checker_id",
        "version",
        "implementation",
        "input_contract",
        "output_contract",
        "claim_class",
        "assumptions",
        "trusted_components",
        "failure_semantics",
        "timeout_semantics",
        "unsupported_semantics",
        "determinism_status",
        "release_status",
        "owner",
    }
    for path in sorted((ROOT / "adapters").glob("*/capability.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        missing = required - set(payload)
        assert not missing, f"{path} missing {sorted(missing)}"
        assert payload["release_status"] in {"stable", "preview", "experimental", "disabled"}
