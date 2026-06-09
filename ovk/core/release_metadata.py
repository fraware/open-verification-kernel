"""Release metadata for OVK."""

from __future__ import annotations

from typing import Any


OVK_RELEASE_CANDIDATE = "0.1.0"


SUPPORTED_COMMANDS = [
    "ovk init",
    "ovk ci",
    "ovk auth-obligation",
    "ovk infra-exposure",
]


SUPPORTED_EVIDENCE_LANES = [
    "self_protection",
    "authorization_obligation",
    "infrastructure_exposure",
]


OPTIONAL_BACKENDS = [
    "opa",
    "z3",
]


def release_metadata() -> dict[str, Any]:
    """Return machine-readable OVK release metadata."""
    return {
        "release_candidate": OVK_RELEASE_CANDIDATE,
        "supported_commands": list(SUPPORTED_COMMANDS),
        "supported_evidence_lanes": list(SUPPORTED_EVIDENCE_LANES),
        "optional_backends": list(OPTIONAL_BACKENDS),
    }
