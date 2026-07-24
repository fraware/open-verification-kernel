"""Permissions extraction for GitHub Actions workflows."""

from __future__ import annotations

from typing import Any

from ovk.compilers.github_actions.ir import PermissionGrant

WRITE_LEVELS = frozenset({"write", "write-all", "admin"})


def extract_permissions(workflow: dict[str, Any]) -> list[PermissionGrant]:
    grants: list[PermissionGrant] = []
    top = workflow.get("permissions")
    grants.extend(_from_block(top, job_id=None))
    jobs = workflow.get("jobs") if isinstance(workflow.get("jobs"), dict) else {}
    for job_id, job in sorted(jobs.items()):
        if not isinstance(job, dict):
            continue
        grants.extend(_from_block(job.get("permissions"), job_id=str(job_id)))
    return grants


def has_write_token(grants: list[PermissionGrant]) -> bool:
    return any(grant.level in WRITE_LEVELS or grant.scope == "write-all" for grant in grants)


def _from_block(block: Any, *, job_id: str | None) -> list[PermissionGrant]:
    if block is None:
        return []
    if isinstance(block, str):
        return [PermissionGrant(scope="all", level=block, job_id=job_id)]
    if not isinstance(block, dict):
        return []
    return [
        PermissionGrant(scope=str(scope), level=str(level), job_id=job_id) for scope, level in sorted(block.items())
    ]
