"""Guarantee-class ordering helpers (never upgrade on normalize/export)."""

from __future__ import annotations

from ovk.assurance.errors import AssuranceError

# Lower rank is weaker. Normalization must never increase rank.
GUARANTEE_RANK: dict[str, int] = {
    "unchecked_advisory": 0,
    "observational": 1,
    "runtime_observed": 1,
    "empirically_measured": 2,
    "human_reviewed": 3,
    "certificate_checked": 4,
    "formally_checked": 5,
}


def assert_no_guarantee_upgrade(declared: str, result_class: str) -> None:
    """Fail closed when result guarantee_class upgrades the declared input class."""
    if declared not in GUARANTEE_RANK or result_class not in GUARANTEE_RANK:
        raise AssuranceError(
            f"unknown guarantee_class for upgrade check: declared={declared!r} result={result_class!r}"
        )
    if GUARANTEE_RANK[result_class] > GUARANTEE_RANK[declared]:
        raise AssuranceError(
            f"normalize/export must not upgrade guarantee_class ({declared!r} -> {result_class!r})"
        )


def clamp_guarantee_class(declared: str, candidate: str) -> str:
    """Return candidate unless it would upgrade declared; then keep declared."""
    if declared not in GUARANTEE_RANK or candidate not in GUARANTEE_RANK:
        return declared
    if GUARANTEE_RANK[candidate] > GUARANTEE_RANK[declared]:
        return declared
    return candidate
