"""Policy interpretation helpers for `.verification/config.yml`."""

from __future__ import annotations

from typing import Any

from ovk.core.router import RoutingConfig, routing_config_from_policy

VALID_DEFAULT_ON_UNKNOWN = frozenset(
    {"require_human_review", "block", "allow_with_warning"}
)


def resolve_default_on_unknown(policy: dict[str, Any] | None) -> str:
    """Return configured unknown-outcome recommendation with a safe default."""
    if not policy:
        return "require_human_review"
    value = policy.get("default_on_unknown", "require_human_review")
    normalized = str(value).strip()
    if normalized not in VALID_DEFAULT_ON_UNKNOWN:
        return "require_human_review"
    return normalized


def bundle_decision_options(policy: dict[str, Any] | None) -> dict[str, Any]:
    """Build keyword arguments for ``make_bundle`` from repository policy."""
    return {"default_on_unknown": resolve_default_on_unknown(policy)}


def resolve_routing_config(policy: dict[str, Any] | None) -> RoutingConfig:
    """Return typed routing configuration from repository policy."""
    return routing_config_from_policy(policy)


def routing_enforced_for_lane(policy: dict[str, Any] | None, lane: str) -> bool:
    """Return True when the lane is listed for enforced control-plane execution."""
    config = resolve_routing_config(policy)
    if lane in config.enforced_lanes:
        return True
    if config.mode == "enforced" and config.enforced_lanes:
        return lane in config.enforced_lanes
    return False
