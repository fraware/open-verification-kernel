"""Extract OVK abstractions from GitHub Actions workflow YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

SECRET_MARKERS = ("${{ secrets.", "${{ secrets[", "secrets.")


def _workflow_on_value(document: dict[str, Any]) -> Any:
    """Return the workflow trigger block from a parsed Actions YAML document.

    PyYAML 1.1 resolves the bare key ``on`` to boolean ``True``, so real workflow
    files often store triggers under ``True`` rather than the string ``"on"``.
    """
    on_value = document.get("on")
    if on_value is None:
        on_value = document.get(True)
    return on_value


def _normalize_triggers(on_value: Any) -> list[str]:
    if isinstance(on_value, str):
        return [on_value]
    if isinstance(on_value, list):
        return [str(item) for item in on_value]
    if isinstance(on_value, dict):
        return [str(key) for key in on_value]
    return []


def _walk_values(value: Any) -> list[Any]:
    items: list[Any] = []
    if isinstance(value, dict):
        items.extend(value.values())
        for nested in value.values():
            items.extend(_walk_values(nested))
    elif isinstance(value, list):
        items.extend(value)
        for nested in value:
            items.extend(_walk_values(nested))
    else:
        items.append(value)
    return items


def _uses_secrets(document: dict[str, Any]) -> bool:
    serialized = str(document)
    return any(marker in serialized for marker in SECRET_MARKERS)


def _pull_request_target_with_pr_head_checkout(document: dict[str, Any]) -> bool:
    triggers = _normalize_triggers(_workflow_on_value(document))
    if "pull_request_target" not in triggers:
        return False
    serialized = str(document.get("jobs", {}))
    markers = (
        "github.event.pull_request.head",
        "refs/pull/",
        "pull_request.head.sha",
    )
    return any(marker in serialized for marker in markers)


def _collect_steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    jobs = document.get("jobs", {})
    if not isinstance(jobs, dict):
        return steps
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_steps = job.get("steps", [])
        if isinstance(job_steps, list):
            for step in job_steps:
                if isinstance(step, dict):
                    steps.append({"job": str(job_name), **step})
    return steps


def workflow_yaml_to_ci_secrets_input(
    yaml_text: str,
    *,
    workflow_id: str = "workflow",
    trust_context: str = "untrusted_fork_pr",
    author_type: str = "unknown",
    agent: str = "unknown",
    task: str = "workflow_yaml_extraction",
) -> dict[str, Any]:
    """Convert GitHub Actions workflow YAML into a CI secrets lane input."""
    document = yaml.safe_load(yaml_text)
    if not isinstance(document, dict):
        raise ValueError("workflow YAML must parse to a mapping")

    return {
        "author_type": author_type,
        "agent": agent,
        "task": task,
        "trust_context": trust_context,
        "workflows": [
            {
                "workflow_id": workflow_id,
                "triggers": _normalize_triggers(_workflow_on_value(document)),
                "permissions": document.get("permissions", {}),
                "steps": _collect_steps(document),
                "uses_secrets": _uses_secrets(document),
                "pull_request_target_with_pr_head_checkout": _pull_request_target_with_pr_head_checkout(document),
            }
        ],
    }


def workflow_path_to_ci_secrets_input(path: Path, **kwargs: Any) -> dict[str, Any]:
    """Load workflow YAML from disk and convert it to CI secrets lane input."""
    return workflow_yaml_to_ci_secrets_input(
        path.read_text(encoding="utf-8"),
        workflow_id=path.stem,
        **kwargs,
    )


def workflow_yaml_to_self_protection_hints(yaml_text: str) -> dict[str, Any]:
    """Extract self-protection-relevant workflow metadata from YAML."""
    document = yaml.safe_load(yaml_text)
    if not isinstance(document, dict):
        raise ValueError("workflow YAML must parse to a mapping")
    permissions = document.get("permissions", {})
    return {
        "workflow_permissions": permissions if isinstance(permissions, dict) else {},
        "triggers": _normalize_triggers(_workflow_on_value(document)),
        "uses_secrets": _uses_secrets(document),
    }
