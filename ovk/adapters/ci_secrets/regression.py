"""Regression artifact generation for CI secrets counterexamples."""

from __future__ import annotations

from typing import Any


def render_ci_secrets_regression_test(counterexample: dict[str, Any], index: int) -> str:
    workflow_id = str(counterexample.get("workflow_id", "unknown"))
    failure_mode = str(counterexample.get("failure_mode", "secrets_exposed_in_untrusted_context"))
    return (
        f"def test_ci_secrets_regression_{index}():\n"
        f"    workflow_id = {workflow_id!r}\n"
        f"    failure_mode = {failure_mode!r}\n"
        "    trust_context = 'untrusted_fork_pr'\n"
        "    uses_secrets_on_untrusted_trigger = True\n"
        "    assert not uses_secrets_on_untrusted_trigger, (\n"
        "        f'ci secrets regression: {workflow_id} triggered {failure_mode}'\n"
        "    )\n"
    )


def render_ci_secrets_regression_suite(counterexamples: list[dict[str, Any]]) -> str:
    if not counterexamples:
        return "# No CI secrets counterexamples were available.\n"
    return (
        "\n\n".join(
            render_ci_secrets_regression_test(counterexample, index)
            for index, counterexample in enumerate(counterexamples)
        )
        + "\n"
    )
