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


def route_intent(intent: dict[str, Any], capabilities: list[dict[str, Any]]) -> dict[str, Any]:
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
            selected.append(
                BackendSelection(
                    backend=tool_name,
                    reason=f"supports domain {domain} and property kind {property_kind}",
                    expected_guarantee=manifest.get("guarantee", {}).get("type", "unknown"),
                    score=1.0,
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
