"""Explicit deployment state-machine schema compiler."""

from __future__ import annotations

from typing import Any

from ovk.compilers.deployment.ir import DeploymentIR, DeploymentState, DeploymentTransition


def compile_explicit_schema(data: dict[str, Any]) -> DeploymentIR:
    states_raw = data.get("states") if isinstance(data.get("states"), list) else []
    transitions_raw = data.get("transitions") if isinstance(data.get("transitions"), list) else []
    required = [str(item) for item in data.get("required_states") or []]
    production = [str(item) for item in data.get("production_states") or []]
    states = [
        DeploymentState(
            name=str(item) if not isinstance(item, dict) else str(item.get("name")),
            production=(str(item) if not isinstance(item, dict) else str(item.get("name"))) in production,
            required=(str(item) if not isinstance(item, dict) else str(item.get("name"))) in required,
        )
        for item in states_raw
    ]
    transitions: list[DeploymentTransition] = []
    unsupported: list[str] = []
    for index, item in enumerate(transitions_raw):
        if not isinstance(item, dict):
            unsupported.append(f"transitions[{index}]_not_object")
            continue
        transitions.append(
            DeploymentTransition(
                source=str(item.get("from") or item.get("source") or ""),
                target=str(item.get("to") or item.get("target") or ""),
                label=str(item.get("label")) if item.get("label") is not None else None,
            )
        )
    warnings: list[str] = []
    if not states:
        warnings.append("states missing")
    if not transitions:
        warnings.append("transitions missing")
    return DeploymentIR(
        source="explicit_schema",
        initial_state=str(data.get("initial_state")) if data.get("initial_state") else None,
        states=states,
        transitions=transitions,
        required_states=required,
        production_states=production,
        warnings=warnings,
        unsupported_constructs=unsupported,
    )
