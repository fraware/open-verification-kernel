"""Infrastructure backends with an honest single deterministic implementation."""

from __future__ import annotations

from ovk.adapters.infrastructure.deterministic_adapter import (
    ADAPTER as INFRASTRUCTURE_DETERMINISTIC_ADAPTER,
)
from ovk.adapters.infrastructure.deterministic_adapter import InfrastructureDeterministicAdapter
from ovk.core.backend_registry import BackendRegistry

INFRASTRUCTURE_BACKENDS = (INFRASTRUCTURE_DETERMINISTIC_ADAPTER,)


def build_infrastructure_registry() -> BackendRegistry:
    """Registry containing infrastructure-deterministic only.

    OPA/Cedar are intentionally absent: they cannot yet compile arbitrary
    infrastructure exposure obligations, so the eligible set records only the
    current authoritative implementation.
    """
    registry = BackendRegistry()
    for adapter in INFRASTRUCTURE_BACKENDS:
        registry.register(adapter)
    return registry


__all__ = [
    "INFRASTRUCTURE_BACKENDS",
    "INFRASTRUCTURE_DETERMINISTIC_ADAPTER",
    "InfrastructureDeterministicAdapter",
    "build_infrastructure_registry",
]
