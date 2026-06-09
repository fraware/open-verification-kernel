"""Normalize raw Z3 authorization results."""

from __future__ import annotations

from typing import Any


VALID_STATUSES = {"pass", "fail", "unknown", "error"}


def normalize_z3_authorization_result(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a raw authorization result from the optional Z3 executor."""
    status = str(raw.get("status", "unknown"))
    if status not in VALID_STATUSES:
        status = "unknown"

    models = raw.get("models", [])
    if not isinstance(models, list):
        models = []

    counterexamples = []
    for model in models:
        if not isinstance(model, dict):
            continue
        counterexamples.append(
            {
                "summary": (
                    f"Non-admin role {model.get('user_role', 'unknown')} can reach "
                    f"admin-only route {model.get('route', 'unknown')}"
                ),
                "failure_mode": "admin_route_reachable_by_non_admin",
                "route": model.get("route"),
                "user_role": model.get("user_role"),
                "path": model.get("path", []),
                "model": model.get("model"),
                "obligation_id": model.get("obligation_id"),
                "query_polarity": model.get("query_polarity"),
            }
        )

    return {
        "status": status,
        "reason": str(raw.get("reason", "")),
        "counterexamples": counterexamples,
    }


def recommendation_from_z3_status(status: str) -> str:
    """Map normalized Z3 status to an OVK merge recommendation."""
    if status == "fail":
        return "block"
    if status in {"unknown", "error"}:
        return "require_human_review"
    return "allow"
