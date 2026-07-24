"""Secret use extraction for GitHub Actions workflows."""

from __future__ import annotations

import json
from typing import Any

from ovk.compilers.github_actions.expressions import secret_names
from ovk.compilers.github_actions.ir import SecretUse


def extract_secrets(workflow: dict[str, Any]) -> list[SecretUse]:
    found: list[SecretUse] = []
    jobs = workflow.get("jobs") if isinstance(workflow.get("jobs"), dict) else {}
    for job_id, job in sorted(jobs.items()):
        if not isinstance(job, dict):
            continue
        found.extend(_scan(job.get("env"), job_id=str(job_id), step_id=None))
        for index, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            step_id = str(step.get("id") or step.get("name") or index)
            found.extend(_scan(step, job_id=str(job_id), step_id=step_id))
        # reusable workflow secrets
        secrets = job.get("secrets")
        if secrets == "inherit":
            found.append(
                SecretUse(
                    name="*",
                    job_id=str(job_id),
                    step_id=None,
                    expression="secrets: inherit",
                )
            )
        elif isinstance(secrets, dict):
            for name, expr in sorted(secrets.items()):
                found.append(
                    SecretUse(
                        name=str(name),
                        job_id=str(job_id),
                        step_id=None,
                        expression=str(expr),
                    )
                )
    return found


def _scan(value: Any, *, job_id: str | None, step_id: str | None) -> list[SecretUse]:
    if value is None:
        return []
    if isinstance(value, str):
        return [SecretUse(name=name, job_id=job_id, step_id=step_id, expression=value) for name in secret_names(value)]
    if isinstance(value, dict):
        found: list[SecretUse] = []
        for nested in value.values():
            found.extend(_scan(nested, job_id=job_id, step_id=step_id))
        return found
    if isinstance(value, list):
        found = []
        for nested in value:
            found.extend(_scan(nested, job_id=job_id, step_id=step_id))
        return found
    # Fallback stringify for unexpected scalars
    return _scan(json.dumps(value), job_id=job_id, step_id=step_id)
