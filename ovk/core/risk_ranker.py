"""Risk ranking for candidate verification intents."""

from __future__ import annotations

from typing import Any

from ovk.core.context import RepositoryContext


CRITICAL_INTENTS = frozenset(
    {
        "agent-cannot-disable-own-ci-gate",
        "no-admin-route-bypass",
        "no-secrets-in-untrusted-context",
    }
)


def rank_intents(
    intents: list[str],
    *,
    context: RepositoryContext,
    compilation_confidence: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    """Return intents sorted by descending risk with scores and metadata."""
    confidence = compilation_confidence or {}
    ranked: list[dict[str, Any]] = []
    surface_domains = {str(surface.get("domain", "")) for surface in context.surfaces}
    high_risk_domains = {"ci_cd", "authorization", "infrastructure"}

    for intent in intents:
        score = 0.5
        if intent in CRITICAL_INTENTS:
            score += 0.35
        if context.actor_type in {"ai_agent", "bot"}:
            score += 0.1
        if surface_domains & high_risk_domains:
            score += 0.05
        score += confidence.get(intent, 0.0) * 0.2
        ranked.append(
            {
                "intent_id": intent,
                "risk_score": min(score, 1.0),
                "critical": intent in CRITICAL_INTENTS,
            }
        )
    ranked.sort(key=lambda item: item["risk_score"], reverse=True)
    return ranked
