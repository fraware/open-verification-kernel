"""Canonical replay of coverage policy bound into typed obligations."""

from __future__ import annotations

from typing import Any

from ovk.compilers.authorization import CoveragePolicy
from ovk.core.execution_models import VerificationObligation

_POLICY_FIELDS = frozenset(
    {
        "accept_partial_coverage",
        "min_complete_confidence",
        "partial_confidence_cap",
        "unknown_confidence",
    }
)


def coverage_policy_payload(policy: CoveragePolicy) -> dict[str, bool | float]:
    """Return the complete canonical policy payload used for replay evidence."""
    return {
        "accept_partial_coverage": policy.accept_partial_coverage,
        "min_complete_confidence": policy.min_complete_confidence,
        "partial_confidence_cap": policy.partial_confidence_cap,
        "unknown_confidence": policy.unknown_confidence,
    }


def _confidence(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"coverage policy field {field!r} must be numeric")
    normalized = float(value)
    if not 0.0 <= normalized <= 1.0:
        raise ValueError(f"coverage policy field {field!r} must be between 0 and 1")
    return normalized


def coverage_policy_from_obligation(obligation: VerificationObligation) -> CoveragePolicy:
    """Reconstruct coverage authorization policy from obligation-bound semantics.

    Authorization compilers bind the policy into ``obligation.abstraction``;
    that abstraction is covered by ``abstraction_digest`` and ``obligation_id``.
    Missing policy uses conservative defaults. Malformed or unexpected bound
    policy is rejected instead of being silently reinterpreted.
    """
    default = CoveragePolicy()
    if obligation.lane != "authorization":
        return default

    raw = obligation.abstraction.get("coverage_policy")
    if raw is None:
        return default
    if not isinstance(raw, dict):
        raise ValueError("obligation-bound coverage_policy must be an object")

    extra = sorted(set(raw) - _POLICY_FIELDS)
    if extra:
        raise ValueError(f"obligation-bound coverage_policy has unknown fields: {extra}")

    accept = raw.get("accept_partial_coverage", default.accept_partial_coverage)
    if not isinstance(accept, bool):
        raise ValueError("coverage policy field 'accept_partial_coverage' must be boolean")

    return CoveragePolicy(
        accept_partial_coverage=accept,
        min_complete_confidence=_confidence(
            raw.get("min_complete_confidence", default.min_complete_confidence),
            field="min_complete_confidence",
        ),
        partial_confidence_cap=_confidence(
            raw.get("partial_confidence_cap", default.partial_confidence_cap),
            field="partial_confidence_cap",
        ),
        unknown_confidence=_confidence(
            raw.get("unknown_confidence", default.unknown_confidence),
            field="unknown_confidence",
        ),
    )
