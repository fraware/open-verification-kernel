"""Verifier registry for assurance describe/lookup (ordinary backends remain ordinary)."""

from __future__ import annotations

from typing import Any

from ovk.adapters.assurance import build_assurance_registry
from ovk.adapters.authorization import build_authorization_registry
from ovk.adapters.ci_secrets import build_ci_secrets_registry
from ovk.adapters.deployment import build_deployment_registry
from ovk.adapters.infrastructure import build_infrastructure_registry
from ovk.adapters.lane import build_default_lane_registry
from ovk.adapters.self_protection import build_self_protection_registry
from ovk.assurance.capability import is_assurance_capable
from ovk.assurance.errors import AssuranceError
from ovk.core.backend_registry import BackendRegistry, BackendRegistryError


def build_verifier_registry(*, include_lanes: bool = True, include_assurance: bool = True) -> BackendRegistry:
    """Register known lane + native/deterministic + assurance backends for describe/lookup.

    Does not register test-only adapters. Ordinary backends remain non-assurance
    unless they advertise a valid assurance section. Assurance-only backends are
    registered for ``ovk verifier`` and are not selected by ordinary routing.
    """
    registry = BackendRegistry()
    builders = [
        build_self_protection_registry,
        build_authorization_registry,
        build_infrastructure_registry,
        build_ci_secrets_registry,
        build_deployment_registry,
    ]
    if include_lanes:
        builders.append(build_default_lane_registry)
    if include_assurance:
        builders.append(build_assurance_registry)

    for builder in builders:
        partial = builder()
        for adapter in partial.all():
            if registry.get(adapter.backend_id) is not None:
                continue
            try:
                registry.register(adapter)
            except BackendRegistryError:
                # Skip duplicates across domain/lane builders.
                continue
    return registry


def lookup_backend(backend: str, registry: BackendRegistry | None = None) -> Any:
    """Return a registered backend adapter or raise AssuranceError."""
    reg = registry or build_verifier_registry()
    adapter = reg.get(backend)
    if adapter is None:
        raise AssuranceError(f"backend not registered: {backend}")
    return adapter


def describe_backend(backend: str, registry: BackendRegistry | None = None) -> dict[str, Any]:
    """Return ordinary capability plus assurance summary for a backend."""
    adapter = lookup_backend(backend, registry=registry)
    manifest = adapter.manifest()
    payload = manifest.model_dump(mode="json", exclude_none=True)
    payload["assurance_capable"] = is_assurance_capable(manifest)
    if hasattr(adapter, "supported_mutation_dimensions") and callable(adapter.supported_mutation_dimensions):
        payload["supported_mutation_dimensions"] = list(adapter.supported_mutation_dimensions())
    elif manifest.assurance is not None:
        payload["supported_mutation_dimensions"] = list(manifest.assurance.mutation_dimensions)
    else:
        payload["supported_mutation_dimensions"] = []
    return payload
