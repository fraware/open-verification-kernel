"""Argo Rollouts deployment compiler."""

from __future__ import annotations

from typing import Any

from ovk.compilers.deployment.ir import DeploymentIR, DeploymentState, DeploymentTransition


def compile_argo_rollouts(rollout: dict[str, Any]) -> DeploymentIR:
    """Compile an Argo Rollout object into a deployment approval IR."""
    spec = rollout.get("spec") if isinstance(rollout.get("spec"), dict) else {}
    strategy = spec.get("strategy") if isinstance(spec.get("strategy"), dict) else {}
    canary = strategy.get("canary") if isinstance(strategy.get("canary"), dict) else {}
    steps = canary.get("steps") if isinstance(canary.get("steps"), list) else []

    states = [
        DeploymentState(name="draft"),
        DeploymentState(name="canary", kind="custom"),
        DeploymentState(name="healthy", kind="approved", required=True),
        DeploymentState(name="deployed", kind="deployed", production=True),
    ]
    transitions = [
        DeploymentTransition(source="draft", target="canary"),
        DeploymentTransition(source="canary", target="healthy"),
        DeploymentTransition(source="healthy", target="deployed"),
    ]
    required = ["healthy"]
    unsupported: list[str] = []
    warnings: list[str] = []
    if not steps:
        warnings.append("canary steps missing")
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            unsupported.append(f"steps[{index}]_not_object")
            continue
        if "analysis" in step or "pause" in step:
            pause_name = f"pause-{index}"
            states.append(DeploymentState(name=pause_name, kind="review", required=True))
            # Insert pause before healthy promotion.
            transitions.append(DeploymentTransition(source="canary", target=pause_name))
            transitions.append(DeploymentTransition(source=pause_name, target="healthy"))
            required.append(pause_name)
    return DeploymentIR(
        source="argo_rollouts",
        initial_state="draft",
        states=states,
        transitions=transitions,
        required_states=sorted(set(required)),
        production_states=["deployed"],
        warnings=warnings,
        unsupported_constructs=unsupported,
    )
