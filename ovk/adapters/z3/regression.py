"""Regression artifact generation for authorization counterexamples."""

from __future__ import annotations

from typing import Any


def render_authorization_regression_test(counterexample: dict[str, Any]) -> str:
    """Render a minimal pytest regression test from an authorization counterexample."""
    route = str(counterexample.get("route", "unknown_route"))
    role = str(counterexample.get("user_role", "unknown_role"))
    return (
        "def test_non_admin_cannot_reach_admin_route():\n"
        f"    route = {route!r}\n"
        f"    role = {role!r}\n"
        "    assert role == 'admin', (\n"
        "        f'authorization regression: non-admin role {role} reached {route}'\n"
        "    )\n"
    )


def render_authorization_regression_suite(counterexamples: list[dict[str, Any]]) -> str:
    """Render a pytest file for one or more authorization counterexamples."""
    if not counterexamples:
        return "# No authorization counterexamples were available.\n"
    tests = []
    for index, counterexample in enumerate(counterexamples):
        test_body = render_authorization_regression_test(counterexample)
        tests.append(
            test_body.replace(
                "test_non_admin_cannot_reach_admin_route", f"test_non_admin_cannot_reach_admin_route_{index}"
            )
        )
    return "\n\n".join(tests) + "\n"
