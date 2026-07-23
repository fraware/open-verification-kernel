"""Self-protection backends with distinct native vs deterministic identities."""

from __future__ import annotations

from ovk.adapters.self_protection.deterministic_adapter import (
    ADAPTER as SELF_PROTECTION_DETERMINISTIC_ADAPTER,
)
from ovk.adapters.self_protection.deterministic_adapter import SelfProtectionDeterministicAdapter
from ovk.adapters.self_protection.opa_adapter import ADAPTER as OPA_NATIVE_ADAPTER
from ovk.adapters.self_protection.opa_adapter import OpaNativeSelfProtectionAdapter
from ovk.core.backend_registry import BackendRegistry

SELF_PROTECTION_BACKENDS = (
    OPA_NATIVE_ADAPTER,
    SELF_PROTECTION_DETERMINISTIC_ADAPTER,
)


def build_self_protection_registry() -> BackendRegistry:
    registry = BackendRegistry()
    for adapter in SELF_PROTECTION_BACKENDS:
        registry.register(adapter)
    return registry


__all__ = [
    "OPA_NATIVE_ADAPTER",
    "SELF_PROTECTION_BACKENDS",
    "SELF_PROTECTION_DETERMINISTIC_ADAPTER",
    "OpaNativeSelfProtectionAdapter",
    "SelfProtectionDeterministicAdapter",
    "build_self_protection_registry",
]
