"""CI secrets exposure adapter and control-plane backends."""

from __future__ import annotations

from ovk.adapters.ci_secrets.deterministic_adapter import (
    ADAPTER as CI_SECRETS_DETERMINISTIC_ADAPTER,
)
from ovk.adapters.ci_secrets.deterministic_adapter import CiSecretsDeterministicAdapter
from ovk.adapters.ci_secrets.evidence import evaluate_ci_secrets_exposure
from ovk.core.backend_registry import BackendRegistry

CI_SECRETS_BACKENDS = (CI_SECRETS_DETERMINISTIC_ADAPTER,)


def build_ci_secrets_registry() -> BackendRegistry:
    """Registry containing ci-secrets-deterministic only.

    OPA/Cedar are intentionally absent until they can compile arbitrary
    CI-secrets obligations.
    """
    registry = BackendRegistry()
    for adapter in CI_SECRETS_BACKENDS:
        registry.register(adapter)
    return registry


__all__ = [
    "CI_SECRETS_BACKENDS",
    "CI_SECRETS_DETERMINISTIC_ADAPTER",
    "CiSecretsDeterministicAdapter",
    "build_ci_secrets_registry",
    "evaluate_ci_secrets_exposure",
]
