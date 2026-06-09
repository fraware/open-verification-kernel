"""Policy configuration for infrastructure exposure checks."""

from __future__ import annotations

from dataclasses import dataclass, field

from ovk.adapters.infra.model import InfraResource


DEFAULT_BLOCKED_SENSITIVITIES = frozenset({"confidential", "restricted"})


@dataclass(frozen=True)
class InfraExposurePolicy:
    """Policy deciding which public resources are violations."""

    blocked_public_sensitivities: frozenset[str] = field(default_factory=lambda: DEFAULT_BLOCKED_SENSITIVITIES)

    def blocks_public_exposure(self, resource: InfraResource) -> bool:
        """Return whether a public resource violates this policy."""
        return resource.public_exposure and resource.sensitivity in self.blocked_public_sensitivities


DEFAULT_INFRA_EXPOSURE_POLICY = InfraExposurePolicy()
