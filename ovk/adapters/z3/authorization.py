"""Z3-style authorization reachability adapter.

This first implementation is deterministic and fixture-driven. It deliberately
uses the same evidence shape that a future Z3 encoding should return, while
avoiding a hard runtime dependency on an installed SMT solver for the first demo.
"""

from __future__ import annotations

from typing import Any

from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


INTENT_ID = "no-admin-route-bypass"
INTENT_TITLE = "No admin route bypass"


def find_authorization_counterexamples(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Find simple route-reachability counterexamples.

    Expected input shape:
    {
      "routes": [
        {"path": "/admin/export", "admin_only_before": true, "admin_only_after": true,
         "reachable_after": [{"role": "user", "via": ["route_group_added"]}]}
      ]
    }
    """
    counterexamples: list[dict[str, Any]] = []
    for route in data.get("routes", []):
        if not route.get("admin_only_before", False):
            continue
        for reachability in route.get("reachable_after", []):
            role = reachability.get("role", "unknown")
            if role != "admin":
                counterexamples.append(
                    {
                        "summary": f"Non-admin role {role} can reach admin-only route {route.get('path')}.",
                        "failure_mode": "admin_route_reachable_by_non_admin",
                        "route": route.get("path"),
                        "user_role": role,
                        "path": reachability.get("via", []),
                    }
                )
    return counterexamples


def evaluate_authorization_reachability(
    data: dict[str, Any],
    *,
    repo: str = "unknown/repo",
    pull_request: int | str | None = None,
    head_sha: str = "unknown",
    base_sha: str | None = None,
) -> VerificationEvidence:
    """Evaluate authorization reachability and return normalized OVK evidence."""
    counterexamples = find_authorization_counterexamples(data)
    status = VerificationStatus.FAIL if counterexamples else VerificationStatus.PASS
    merge_recommendation = "block" if counterexamples else "allow"

    subject: dict[str, Any] = {"repo": repo, "head_sha": head_sha}
    if pull_request is not None:
        subject["pull_request"] = pull_request
    if base_sha is not None:
        subject["base_sha"] = base_sha

    return VerificationEvidence(
        evidence_id="ev-auth-reachability",
        schema_version="ovk.evidence.v1",
        subject=subject,
        change_origin={
            "author_type": data.get("author_type", "unknown"),
            "agent": data.get("agent", "unknown"),
            "task": data.get("task", "unknown"),
        },
        intent={
            "intent_id": INTENT_ID,
            "title": INTENT_TITLE,
            "risk": {"severity": "high"},
        },
        backend_claims=[
            BackendClaim(
                backend="z3",
                guarantee_type="smt_reachability_fixture",
                status=status,
                assumptions=[
                    "Route reachability abstraction is supplied by the input fixture.",
                    "The check looks for a non-admin principal reaching a route marked admin-only before the change.",
                    "Future versions should encode this abstraction as an SMT satisfiability query.",
                ],
                limits=[
                    "This first adapter does not parse application code directly.",
                    "This first adapter does not prove end-to-end authorization semantics.",
                ],
                adapter_version="0.1.0",
            )
        ],
        counterexamples=counterexamples,
        generated_artifacts=[
            {
                "kind": "regression_unit_test",
                "path": ".verification/generated_tests/test_no_admin_route_bypass.py",
            }
        ]
        if counterexamples
        else [],
        decision={
            "merge_recommendation": merge_recommendation,
            "human_review_required": bool(counterexamples),
            "override_allowed": bool(counterexamples),
            "override_requires": ["maintainer", "security-review"] if counterexamples else [],
        },
    )
