"""Assurance capability helpers."""

from __future__ import annotations

from ovk.core.backend_registry import BackendRegistryError, _validate_assurance_section
from ovk.core.execution_models import BackendCapabilityManifest


def is_assurance_capable(manifest: BackendCapabilityManifest | None) -> bool:
    """Return True when the manifest advertises assurance_capable=True."""
    if manifest is None or manifest.assurance is None:
        return False
    return bool(manifest.assurance.assurance_capable)


def validate_assurance_claim(manifest: BackendCapabilityManifest) -> None:
    """Validate assurance claim consistency; raise on contradiction."""
    try:
        _validate_assurance_section(manifest)
    except BackendRegistryError as exc:
        raise ValueError(str(exc)) from exc
    if manifest.assurance is not None and manifest.assurance.assurance_capable:
        if not is_assurance_capable(manifest):
            raise ValueError("assurance_capable claim failed validation")
