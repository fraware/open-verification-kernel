"""Regression artifact generation for infrastructure exposure counterexamples."""

from __future__ import annotations

from typing import Any


def render_infra_regression_test(counterexample: dict[str, Any]) -> str:
    """Render one pytest regression test from an infra exposure counterexample."""
    resource_id = str(counterexample.get("resource_id", "unknown_resource"))
    sensitivity = str(counterexample.get("sensitivity", "unknown"))
    return (
        "def test_sensitive_resource_is_not_publicly_exposed():\n"
        f"    resource_id = {resource_id!r}\n"
        f"    sensitivity = {sensitivity!r}\n"
        "    public_exposure = True\n"
        "    assert not (sensitivity in {'confidential', 'restricted'} and public_exposure), (\n"
        "        f'infrastructure regression: {resource_id} is publicly exposed'\n"
        "    )\n"
    )


def render_infra_regression_suite(counterexamples: list[dict[str, Any]]) -> str:
    """Render a pytest file for infrastructure exposure counterexamples."""
    if not counterexamples:
        return "# No infrastructure exposure counterexamples were available.\n"
    tests = []
    for index, counterexample in enumerate(counterexamples):
        test_body = render_infra_regression_test(counterexample)
        tests.append(
            test_body.replace(
                "test_sensitive_resource_is_not_publicly_exposed",
                f"test_sensitive_resource_is_not_publicly_exposed_{index}",
            )
        )
    return "\n\n".join(tests) + "\n"
