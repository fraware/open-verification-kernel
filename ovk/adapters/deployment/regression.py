"""Regression artifact generation for deployment state counterexamples."""

from __future__ import annotations

from typing import Any


def render_deployment_regression_test(counterexample: dict[str, Any], index: int) -> str:
    skipped = counterexample.get("skipped_required_states", [])
    production_state = str(counterexample.get("production_state", "deployed"))
    return (
        f"def test_deployment_state_regression_{index}():\n"
        f"    skipped_required_states = {skipped!r}\n"
        f"    production_state = {production_state!r}\n"
        "    assert not skipped_required_states, (\n"
        "        f'deployment regression: production reached {production_state} '\n"
        "        f'without states {skipped_required_states}'\n"
        "    )\n"
    )


def render_deployment_regression_suite(counterexamples: list[dict[str, Any]]) -> str:
    if not counterexamples:
        return "# No deployment state counterexamples were available.\n"
    return (
        "\n\n".join(
            render_deployment_regression_test(counterexample, index)
            for index, counterexample in enumerate(counterexamples)
        )
        + "\n"
    )
