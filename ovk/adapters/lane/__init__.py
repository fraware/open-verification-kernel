"""Lane adapter package: wrappers around existing evaluators for registry use."""

from __future__ import annotations

from ovk.adapters.lane.authorization_adapter import ADAPTER as AUTHORIZATION_LANE_ADAPTER
from ovk.adapters.lane.authorization_adapter import AuthorizationLaneAdapter
from ovk.adapters.lane.ci_secrets_adapter import ADAPTER as CI_SECRETS_LANE_ADAPTER
from ovk.adapters.lane.ci_secrets_adapter import CiSecretsLaneAdapter
from ovk.adapters.lane.deployment_adapter import ADAPTER as DEPLOYMENT_LANE_ADAPTER
from ovk.adapters.lane.deployment_adapter import DeploymentLaneAdapter
from ovk.adapters.lane.infrastructure_adapter import ADAPTER as INFRASTRUCTURE_LANE_ADAPTER
from ovk.adapters.lane.infrastructure_adapter import InfrastructureLaneAdapter
from ovk.adapters.lane.self_protection_adapter import ADAPTER as SELF_PROTECTION_LANE_ADAPTER
from ovk.adapters.lane.self_protection_adapter import SelfProtectionLaneAdapter
from ovk.core.backend_registry import BackendRegistry

LANE_ADAPTERS = (
    SELF_PROTECTION_LANE_ADAPTER,
    AUTHORIZATION_LANE_ADAPTER,
    INFRASTRUCTURE_LANE_ADAPTER,
    CI_SECRETS_LANE_ADAPTER,
    DEPLOYMENT_LANE_ADAPTER,
)


def build_default_lane_registry() -> BackendRegistry:
    """Return a registry containing the five operational lane wrappers."""
    registry = BackendRegistry()
    for adapter in LANE_ADAPTERS:
        registry.register(adapter)
    return registry


__all__ = [
    "AUTHORIZATION_LANE_ADAPTER",
    "AuthorizationLaneAdapter",
    "CI_SECRETS_LANE_ADAPTER",
    "CiSecretsLaneAdapter",
    "DEPLOYMENT_LANE_ADAPTER",
    "DeploymentLaneAdapter",
    "INFRASTRUCTURE_LANE_ADAPTER",
    "InfrastructureLaneAdapter",
    "LANE_ADAPTERS",
    "SELF_PROTECTION_LANE_ADAPTER",
    "SelfProtectionLaneAdapter",
    "build_default_lane_registry",
]
