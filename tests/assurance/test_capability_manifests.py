"""Capability manifest validation for ordinary + assurance sections."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.adapters.lane import build_default_lane_registry
from ovk.assurance.capability import is_assurance_capable, validate_assurance_claim
from ovk.core.backend_registry import BackendRegistry, BackendRegistryError
from ovk.core.execution_models import BackendCapabilityManifest
from ovk.core.schema_validation import load_json, validate_against_schema
from ovk.paths import schema_path
from tests.assurance.support.digest_adapter import DigestPredicateAdapter

FIXTURES = Path(__file__).parent / "fixtures"


def test_existing_lane_adapter_manifests_still_validate() -> None:
    schema = load_json(schema_path("verification.capability.schema.json"))
    registry = build_default_lane_registry()
    for adapter in registry.all():
        payload = adapter.manifest().model_dump(mode="json", exclude_none=True)
        report = validate_against_schema(payload, schema)
        assert report.valid, f"{adapter.backend_id}: {report.issues}"
        assert adapter.manifest().assurance is None
        assert not is_assurance_capable(adapter.manifest())


def test_valid_assurance_fixture_validates() -> None:
    schema = load_json(schema_path("verification.capability.schema.json"))
    payload = json.loads((FIXTURES / "valid_assurance_capability.json").read_text(encoding="utf-8"))
    report = validate_against_schema(payload, schema)
    assert report.valid, report.issues
    model = BackendCapabilityManifest.model_validate(payload)
    assert is_assurance_capable(model)
    validate_assurance_claim(model)


def test_invalid_assurance_capable_without_snapshot_fails_schema_and_registry() -> None:
    schema = load_json(schema_path("verification.capability.schema.json"))
    payload = json.loads(
        (FIXTURES / "invalid_assurance_capable_without_snapshot.json").read_text(encoding="utf-8")
    )
    report = validate_against_schema(payload, schema)
    assert not report.valid

    model = BackendCapabilityManifest.model_validate(payload)
    with pytest.raises((ValueError, BackendRegistryError)):
        validate_assurance_claim(model)

    adapter = DigestPredicateAdapter()
    # Force a bad manifest via a wrapper.
    class Broken(DigestPredicateAdapter):
        def manifest(self) -> BackendCapabilityManifest:
            return model

    registry = BackendRegistry()
    with pytest.raises(BackendRegistryError):
        registry.register(Broken())


def test_digest_adapter_registers_with_assurance() -> None:
    registry = BackendRegistry()
    adapter = DigestPredicateAdapter(expected_digest="sha256:" + ("a" * 64))
    registry.register(adapter)
    assert is_assurance_capable(adapter.manifest())
    assert registry.get(adapter.backend_id) is adapter
