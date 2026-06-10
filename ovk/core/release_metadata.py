"""Release metadata for OVK."""

from __future__ import annotations

from typing import Any


OVK_VERSION = "1.2.0"
OVK_RELEASE_CANDIDATE = OVK_VERSION


SUPPORTED_COMMANDS = [
    "ovk init",
    "ovk check",
    "ovk doctor",
    "ovk run",
    "ovk generate-test",
    "ovk repair-suggest",
    "ovk ci",
    "ovk auth-obligation",
    "ovk infra-exposure",
    "ovk ci-secrets",
    "ovk deployment-state",
    "ovk release-bundle",
    "ovk release-preflight",
    "ovk evidence-quality",
    "ovk validate-outputs",
    "ovk verify",
    "ovk extract-workflow",
    "ovk plan",
    "ovk infer",
    "ovk template list",
    "ovk template show",
    "ovk template apply",
    "ovk bench",
    "ovk pilot",
]


SUPPORTED_EVIDENCE_LANES = [
    "self_protection",
    "authorization_obligation",
    "infrastructure_exposure",
    "ci_secrets_exposure",
    "deployment_approval_state",
]


OPTIONAL_BACKENDS = [
    "opa",
    "z3",
    "cedar",
    "tla+",
    "kani",
    "dafny",
    "verus",
    "lean",
    "cbmc",
    "alloy",
]


def release_metadata() -> dict[str, Any]:
    """Return machine-readable OVK release metadata."""
    return {
        "version": OVK_VERSION,
        "release_candidate": OVK_RELEASE_CANDIDATE,
        "supported_commands": list(SUPPORTED_COMMANDS),
        "supported_evidence_lanes": list(SUPPORTED_EVIDENCE_LANES),
        "optional_backends": list(OPTIONAL_BACKENDS),
    }
