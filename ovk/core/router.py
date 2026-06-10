"""Backend routing for verification intents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BackendSelection:
    """A selected backend and the reason it was selected."""

    backend: str
    reason: str
    expected_guarantee: str
    required: bool = True
    score: float = 0.0


@dataclass(frozen=True)
class BackendRejection:
    """A backend that was considered and rejected."""

    backend: str
    reason: str


DETERMINISTIC_PREFERRED_BACKENDS: frozenset[str] = frozenset({"deterministic", "opa", "z3"})
PREFER_DETERMINISTIC_BONUS = 0.3
PREFER_DETERMINISTIC_PENALTY = 0.15


@dataclass(frozen=True)
class VerificationBudget:
    """Runtime budget for backend execution."""

    max_wall_time_seconds: float = 30.0
    max_memory_mb: int = 512
    allowed_backends: frozenset[str] | None = None
    denied_backends: frozenset[str] = frozenset()
    prefer_deterministic: bool = False


BACKEND_COST_PRIORS: dict[str, float] = {
    "deterministic": 0.05,
    "opa": 0.25,
    "z3": 0.45,
    "cedar": 0.2,
    "tla+": 0.55,
    "kani": 0.5,
    "dafny": 0.7,
    "verus": 0.7,
    "lean": 0.8,
    "cbmc": 0.6,
    "alloy": 0.55,
}


def _utility_score(
    manifest: dict[str, Any],
    *,
    budget: VerificationBudget | None,
    historical_priors: dict[str, float] | None = None,
    surface_bonuses: dict[str, float] | None = None,
) -> float:
    tool_name = str(manifest.get("tool", {}).get("name", "unknown"))
    relevance = 1.0
    guarantee_strength = 0.7 if manifest.get("guarantee", {}).get("type") == "policy_evaluation" else 0.5
    historical_success = (historical_priors or {}).get(tool_name, 0.5)
    surface_bonus = (surface_bonuses or {}).get(tool_name, 0.0)
    cost = BACKEND_COST_PRIORS.get(tool_name, 0.4)
    budget_penalty = 0.0
    deterministic_adjustment = 0.0
    if budget is not None:
        if budget.allowed_backends is not None and tool_name not in budget.allowed_backends:
            return -1.0
        if tool_name in budget.denied_backends:
            return -1.0
        if cost * 30 > budget.max_wall_time_seconds:
            budget_penalty = 0.3
        if tool_name in DETERMINISTIC_PREFERRED_BACKENDS:
            if budget.prefer_deterministic:
                deterministic_adjustment = PREFER_DETERMINISTIC_BONUS
            else:
                deterministic_adjustment = -PREFER_DETERMINISTIC_PENALTY
    return (
        relevance
        + guarantee_strength
        + (0.15 * historical_success)
        + surface_bonus
        + deterministic_adjustment
        - cost
        - budget_penalty
    )


def route_intent(
    intent: dict[str, Any],
    capabilities: list[dict[str, Any]],
    *,
    budget: VerificationBudget | None = None,
    historical_priors: dict[str, float] | None = None,
    surface_bonuses: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Route an intent to candidate backends using manifest metadata.

    This is intentionally rule-based for v0. Later versions can add historical
    success, runtime cost, repository policy, and benchmark-derived priors.
    """
    domain = intent.get("domain")
    property_kind = intent.get("property", {}).get("kind")
    selected: list[BackendSelection] = []
    rejected: list[BackendRejection] = []

    for manifest in capabilities:
        tool_name = manifest.get("tool", {}).get("name", "unknown")
        domains = set(manifest.get("supported_domains", []))
        property_kinds = set(manifest.get("supported_property_kinds", []))
        domain_match = domain in domains
        kind_match = property_kind in property_kinds

        if domain_match and kind_match:
            score = _utility_score(
                manifest,
                budget=budget,
                historical_priors=historical_priors,
                surface_bonuses=surface_bonuses,
            )
            if score < 0:
                rejected.append(BackendRejection(backend=tool_name, reason="excluded by verification budget"))
                continue
            selected.append(
                BackendSelection(
                    backend=tool_name,
                    reason=f"supports domain {domain} and property kind {property_kind}",
                    expected_guarantee=manifest.get("guarantee", {}).get("type", "unknown"),
                    score=score,
                )
            )
        elif domain_match:
            rejected.append(
                BackendRejection(
                    backend=tool_name,
                    reason=f"supports domain {domain} but not property kind {property_kind}",
                )
            )
        else:
            rejected.append(
                BackendRejection(
                    backend=tool_name,
                    reason=f"does not support domain {domain}",
                )
            )

    selected_sorted = sorted(selected, key=lambda item: item.score, reverse=True)
    return {
        "intent_id": intent.get("intent_id", "unknown"),
        "selected": [item.__dict__ for item in selected_sorted],
        "rejected": [item.__dict__ for item in rejected],
    }
