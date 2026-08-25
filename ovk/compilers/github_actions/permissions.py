"""Permissions extraction and effective-principal semantics for GitHub Actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from ovk.compilers.github_actions.ir import PermissionGrant

WRITE_LEVELS = frozenset({"write", "write-all", "admin"})
PermissionSource = Literal["job", "workflow", "default"]
PermissionCeilingMode = Literal["exact", "privileged_default", "unresolved_default"]


@dataclass(frozen=True)
class PermissionCeiling:
    """Upper bound on token authority passed into a reusable workflow."""

    mode: PermissionCeilingMode
    grants: tuple[PermissionGrant, ...] = ()
    source: str = ""


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


def has_write_token(grants: list[PermissionGrant] | tuple[PermissionGrant, ...]) -> bool:
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


def permission_ceiling_for_job(
    workflow: dict[str, Any],
    job_id: str,
    *,
    triggers: set[str] | frozenset[str],
) -> PermissionCeiling:
    """Return the token-authority ceiling a reusable call job can pass onward."""
    grants, source = effective_permissions_for_job(workflow, job_id)
    if source != "default":
        return PermissionCeiling(mode="exact", grants=tuple(grants), source=source)
    if "pull_request_target" in triggers:
        return PermissionCeiling(mode="privileged_default", source="pull_request_target_default")
    return PermissionCeiling(mode="unresolved_default", source="repository_default_unresolved")


def effective_permissions_under_ceiling(
    workflow: dict[str, Any],
    job_id: str,
    *,
    ceiling: PermissionCeiling,
) -> tuple[list[PermissionGrant], str, bool, PermissionCeiling, bool]:
    """Contract a called job's requested permissions to the caller's ceiling.

    Returns ``(effective_grants, source, write_risk, next_ceiling, unresolved)``.
    Called workflows may maintain or reduce caller authority but never elevate it.
    """
    requested, requested_source = effective_permissions_for_job(workflow, job_id)

    if ceiling.mode == "exact":
        if requested_source == "default":
            effective = [_rebind(grant, job_id=job_id) for grant in ceiling.grants]
        else:
            effective = _intersect_grants(ceiling.grants, requested, job_id=job_id)
        source = f"reusable:{ceiling.source}->{requested_source}"
        next_ceiling = PermissionCeiling(mode="exact", grants=tuple(effective), source=source)
        return effective, source, has_write_token(effective), next_ceiling, False

    if ceiling.mode == "privileged_default":
        if requested_source == "default":
            source = "reusable:pull_request_target_default"
            return [], source, True, PermissionCeiling(mode="privileged_default", source=source), False
        effective = [_rebind(grant, job_id=job_id) for grant in requested]
        source = f"reusable:pull_request_target_default->{requested_source}"
        next_ceiling = PermissionCeiling(mode="exact", grants=tuple(effective), source=source)
        return effective, source, has_write_token(effective), next_ceiling, False

    # Repository/event default is unresolved. An explicit read-only or empty
    # called-workflow block is sufficient to establish no write authority. An
    # explicit write request remains only an upper bound because the caller may
    # not possess that authority in the first place.
    if requested_source == "default":
        source = "reusable:repository_default_unresolved"
        return [], source, False, PermissionCeiling(mode="unresolved_default", source=source), True

    effective = [_rebind(grant, job_id=job_id) for grant in requested]
    source = f"reusable:repository_default_unresolved->{requested_source}"
    if has_write_token(effective):
        return effective, source, False, PermissionCeiling(mode="unresolved_default", grants=tuple(effective), source=source), True
    next_ceiling = PermissionCeiling(mode="exact", grants=tuple(effective), source=source)
    return effective, source, False, next_ceiling, False


def _rebind(grant: PermissionGrant, *, job_id: str) -> PermissionGrant:
    return PermissionGrant(scope=grant.scope, level=grant.level, job_id=job_id)


def _level_rank(level: str, *, scope: str) -> int:
    normalized = str(level).strip().lower()
    if normalized in {"write", "write-all", "admin"}:
        return 2
    if normalized in {"read", "read-all"}:
        if scope == "id-token":
            return 0
        return 1
    return 0


def _grant_level(grants: tuple[PermissionGrant, ...] | list[PermissionGrant], scope: str) -> int:
    specific = [grant for grant in grants if str(grant.scope).strip().lower() == scope]
    if specific:
        return max(_level_rank(grant.level, scope=scope) for grant in specific)
    all_grants = [grant for grant in grants if str(grant.scope).strip().lower() == "all"]
    if not all_grants:
        return 0
    return max(_level_rank(grant.level, scope=scope) for grant in all_grants)


def _explicit_scopes(grants: tuple[PermissionGrant, ...] | list[PermissionGrant]) -> set[str]:
    return {
        str(grant.scope).strip().lower()
        for grant in grants
        if str(grant.scope).strip().lower() not in {"all", "write-all"}
    }


def _intersect_grants(
    ceiling: tuple[PermissionGrant, ...] | list[PermissionGrant],
    requested: list[PermissionGrant],
    *,
    job_id: str,
) -> list[PermissionGrant]:
    requested_all = any(str(grant.scope).strip().lower() == "all" for grant in requested)
    ceiling_all = any(str(grant.scope).strip().lower() == "all" for grant in ceiling)

    if requested_all and ceiling_all:
        rank = min(_grant_level(ceiling, "contents"), _grant_level(requested, "contents"))
        if rank == 0:
            return []
        return [PermissionGrant(scope="all", level="write-all" if rank == 2 else "read-all", job_id=job_id)]

    scopes = _explicit_scopes(ceiling) if requested_all else _explicit_scopes(requested)
    effective: list[PermissionGrant] = []
    for scope in sorted(scopes):
        rank = min(_grant_level(ceiling, scope), _grant_level(requested, scope))
        if rank == 0:
            continue
        effective.append(PermissionGrant(scope=scope, level="write" if rank == 2 else "read", job_id=job_id))
    return effective


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
