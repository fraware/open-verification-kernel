"""OVK verifier-assurance package (VA-01 through VA-14).

Ordinary ``ovk check`` / MCP paths are intentionally untouched. Assurance
surfaces are opt-in via ``ovk verifier …`` and require a resolved PCS pin.

Heavy imports (registry, conformance, adjudication) are available as submodules
to avoid circular imports with assurance adapters.
"""

from __future__ import annotations

from ovk.assurance.capability import is_assurance_capable, validate_assurance_claim
from ovk.assurance.errors import (
    AssuranceError,
    EvidenceError,
    MutationError,
    PinError,
    ReplayError,
)
from ovk.assurance.pin import require_pcs_pin, resolve_pcs_root
from ovk.assurance.snapshot import ConfigurationSnapshot, build_configuration_snapshot

__all__ = [
    "AssuranceError",
    "ConfigurationSnapshot",
    "EvidenceError",
    "MutationError",
    "PinError",
    "ReplayError",
    "build_configuration_snapshot",
    "is_assurance_capable",
    "require_pcs_pin",
    "resolve_pcs_root",
    "validate_assurance_claim",
]
