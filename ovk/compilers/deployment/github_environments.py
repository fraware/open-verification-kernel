"""GitHub Environments deployment compiler."""

from __future__ import annotations

from typing import Any

from ovk.compilers.deployment.ir import DeploymentIR, DeploymentState, DeploymentTransition


def compile_github_environments(data: dict[str, Any]) -> DeploymentIR:
    """Compile GitHub environment protection rules into a deployment IR.

    Expected shape::
        {
          "environments": [
            {"name": "staging", "required_reviewers": 1},
            {"name": "production", "required_reviewers": 2, "production": true}
          ]
        }
    """
    envs = data.get("environments") if isinstance(data.get("environments"), list) else []
    states = [DeploymentState(name="draft")]
    transitions: list[DeploymentTransition] = []
    required: list[str] = []
    production: list[str] = []
    prev = "draft"
    for env in envs:
        if not isinstance(env, dict) or not env.get("name"):
            continue
        name = str(env["name"])
        is_prod = bool(env.get("production") or name.lower() in {"prod", "production"})
        needs_review = int(env.get("required_reviewers") or 0) > 0
        states.append(
            DeploymentState(
                name=name,
                kind="deployed" if is_prod else "custom",
                production=is_prod,
                required=needs_review,
            )
        )
        if needs_review:
            review_name = f"{name}-review"
            states.append(DeploymentState(name=review_name, kind="review", required=True))
            transitions.append(DeploymentTransition(source=prev, target=review_name))
            transitions.append(DeploymentTransition(source=review_name, target=name))
            required.append(review_name)
            prev = name
        else:
            transitions.append(DeploymentTransition(source=prev, target=name))
            prev = name
        if is_prod:
            production.append(name)
    warnings = [] if envs else ["environments missing"]
    return DeploymentIR(
        source="github_environments",
        initial_state="draft",
        states=states,
        transitions=transitions,
        required_states=required,
        production_states=production,
        warnings=warnings,
    )
