"""Authorization-specific backends with distinct guarantee classes."""

from __future__ import annotations

from ovk.adapters.authorization.deterministic_adapter import (
    ADAPTER as AUTHORIZATION_DETERMINISTIC_ADAPTER,
)
from ovk.adapters.authorization.deterministic_adapter import AuthorizationDeterministicAdapter
from ovk.adapters.authorization.z3_adapter import ADAPTER as Z3_NATIVE_ADAPTER
from ovk.adapters.authorization.z3_adapter import Z3NativeAuthorizationAdapter
from ovk.core.backend_registry import BackendRegistry

AUTHORIZATION_BACKENDS = (
    Z3_NATIVE_ADAPTER,
    AUTHORIZATION_DETERMINISTIC_ADAPTER,
)


def build_authorization_registry() -> BackendRegistry:
    """Registry containing z3-native and authorization-deterministic only."""
    registry = BackendRegistry()
    for adapter in AUTHORIZATION_BACKENDS:
        registry.register(adapter)
    return registry


__all__ = [
    "AUTHORIZATION_BACKENDS",
    "AUTHORIZATION_DETERMINISTIC_ADAPTER",
    "AuthorizationDeterministicAdapter",
    "Z3_NATIVE_ADAPTER",
    "Z3NativeAuthorizationAdapter",
    "build_authorization_registry",
]
