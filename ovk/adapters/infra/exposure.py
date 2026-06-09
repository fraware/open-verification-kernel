"""Deterministic infrastructure exposure checker."""

from __future__ import annotations

from typing import Any

from ovk.adapters.infra.model import InfraResource, load_resources
from ovk.adapters.infra.policy import DEFAULT_INFRA_EXPOSURE_POLICY, InfraExposurePolicy


FAILURE_MODE = "sensitive_resource_publicly_exposed"


def find_exposure_counterexamples(
    data: dict[str, Any],
    policy: InfraExposurePolicy = DEFAULT_INFRA_EXPOSURE_POLICY,
) -> list[dict[str, Any]]:
    """Find resources that violate the exposure policy."""
    counterexamples: list[dict[str, Any]] = []
    for resource in load_resources(data):
        if policy.blocks_public_exposure(resource):
            counterexamples.append(counterexample_from_resource(resource))
    return counterexamples


def counterexample_from_resource(resource: InfraResource) -> dict[str, Any]:
    """Render an exposed resource as an OVK counterexample."""
    return {
        "summary": f"Sensitive resource {resource.resource_id} is publicly exposed.",
        "failure_mode": FAILURE_MODE,
        "resource_id": resource.resource_id,
        "resource_type": resource.resource_type,
        "sensitivity": resource.sensitivity,
        "exposure_paths": resource.exposure_paths,
    }
