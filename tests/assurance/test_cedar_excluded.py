"""Cedar and ordinary lane adapters must remain non-assurance."""

from __future__ import annotations

import json

from ovk.adapters.assurance import build_assurance_registry
from ovk.adapters.lane import build_default_lane_registry
from ovk.assurance.capability import is_assurance_capable
from ovk.core.execution_models import BackendCapabilityManifest
from ovk.paths import resource_path


def test_cedar_is_not_assurance_capable() -> None:
    payload = json.loads(resource_path("adapters", "cedar", "capability.json").read_text(encoding="utf-8"))
    cedar = BackendCapabilityManifest.model_validate(payload)
    assert not is_assurance_capable(cedar)
    assert cedar.assurance is None


def test_ordinary_lane_registry_excludes_assurance_backends() -> None:
    lane_ids = {adapter.backend_id for adapter in build_default_lane_registry().all()}
    assurance_ids = {adapter.backend_id for adapter in build_assurance_registry().all()}
    assert lane_ids.isdisjoint(assurance_ids)
    assert "cedar" not in assurance_ids
    assert "auth-state-predicate" not in lane_ids
    assert "opa-policy" not in lane_ids
    assert "pytest-suite" not in lane_ids
