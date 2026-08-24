"""Permissions extraction and effective-principal semantics for GitHub Actions."""

from __future__ import annotations

from typing import Any, Literal

from ovk.compilers.github_actions.ir import PermissionGrant

WRITE_LEVELS = frozenset({"write", "write-all", "admin"})
PermissionSource = Literal["job", "workflow", "default"]


def extract_permissions(workflow: dict[str, Any]) -> list[PermissionGrant]:
    """Extract declared workflow- and job-level permission blocks.

    This is a declaration inventory only. Use ``effective_permissions_for_job``
    when reasoning about the token available to a specific job.
    """
    grants: list[PermissionGrant] = []
    top = workflow.get("permissions")
    grants.extend(_from_block(top, job_id=None))
    jobs = workflow.get("jobs") if isinstance(workflow.get("jobs"), dict) else {}
    for job_id, job in sorted(jobs.items()):
        if not isinstance(job, dict):
            continue
        grants.extend(_from_block(job.get("permissions"), job_id=str(job_id)))
    return grants


def effective_permissions_for_job(
    workflow: dict[str, Any],
    job_id: str,
) -> tuple[list[PermissionGrant], PermissionSource]:
    """Return the effective *declared* permissions for one job.

    GitHub applies workflow permissions first and then job permissions. Once a
    permissions block is specified, omitted scopes become ``none``. Therefore a
    job-level block replaces the workflow-level grant set for effective static
    reasoning; it must not be unioned with grants from another job.

    ``default`` means neither level declares permissions. The effective token is
    then repository/event dependent and must not be silently classified as
    read-only or write-capable by this helper.
    """
    jobs = workflow.get("jobs") if isinstance(workflow.get("jobs"), dict) else {}
    job = jobs.get(job_id)
    if isinstance(job, dict) and "permissions" in job:
        return _from_block(job.get("permissions"), job_id=job_id), "job"
    if "permissions" in workflow:
        return _from_block(workflow.get("permissions"), job_id=job_id), "workflow"
    return [], "default"


def has_write_token(grants: list[PermissionGrant]) -> bool:
    """Return True when the supplied effective grant set contains write access."""
    for grant in grants:
        level = str(grant.level).strip().lower()
        scope = str(grant.scope).strip().lower()
        if level in WRITE_LEVELS or scope == "write-all":
            return True
    return False


def job_write_token_risk(
    workflow: dict[str, Any],
    job_id: str,
    *,
    triggers: set[str] | frozenset[str],
) -> tuple[bool, str]:
    """Return whether a job can be statically treated as write-token capable.

    Explicit job/workflow permissions are authoritative for static analysis.
    When no permissions are declared, ``pull_request_target`` is treated as a
    privileged default-token risk because GitHub grants base-repository trust to
    that event (subject to repository/organization restrictions). Other default
    cases remain unresolved instead of being guessed.
    """
    grants, source = effective_permissions_for_job(workflow, job_id)
    if source != "default":
        return has_write_token(grants), source
    if "pull_request_target" in triggers:
        return True, "pull_request_target_default"
    return False, "repository_default_unresolved"


def _from_block(block: Any, *, job_id: str | None) -> list[PermissionGrant]:
    if block is None:
        return []
    if isinstance(block, str):
        value = block.strip().lower()
        if value == "read-all":
            return [PermissionGrant(scope="all", level="read-all", job_id=job_id)]
        if value == "write-all":
            return [PermissionGrant(scope="all", level="write-all", job_id=job_id)]
        return [PermissionGrant(scope="all", level=value, job_id=job_id)]
    if not isinstance(block, dict):
        return []
    return [
        PermissionGrant(scope=str(scope), level=str(level).strip().lower(), job_id=job_id)
        for scope, level in sorted(block.items())
    ]
