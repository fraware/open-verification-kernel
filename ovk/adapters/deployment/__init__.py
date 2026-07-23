"""Deployment approval state machine adapter and control-plane backends."""

from __future__ import annotations

from ovk.adapters.deployment.deterministic_adapter import (
    ADAPTER as DEPLOYMENT_DETERMINISTIC_ADAPTER,
)
from ovk.adapters.deployment.deterministic_adapter import DeploymentDeterministicAdapter
from ovk.adapters.deployment.evidence import evaluate_approval_state_machine
from ovk.core.backend_registry import BackendRegistry

DEPLOYMENT_BACKENDS = (DEPLOYMENT_DETERMINISTIC_ADAPTER,)


def build_deployment_registry() -> BackendRegistry:
    """Registry containing deployment-deterministic only.

    Additional model checkers are intentionally absent until they can compile
    arbitrary deployment obligations.
    """
    registry = BackendRegistry()
    for adapter in DEPLOYMENT_BACKENDS:
        registry.register(adapter)
    return registry


__all__ = [
    "DEPLOYMENT_BACKENDS",
    "DEPLOYMENT_DETERMINISTIC_ADAPTER",
    "DeploymentDeterministicAdapter",
    "build_deployment_registry",
    "evaluate_approval_state_machine",
]
