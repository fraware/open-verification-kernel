"""Trust-flow analysis for GitHub Actions workflows.

Property: untrusted code executing with a protected secret, write token,
protected environment, or privileged capability is a finding.

Token authority is evaluated per job and across reusable-workflow call edges.
A called workflow inherits a permission ceiling from its caller and may only
maintain or reduce that authority. Secret availability is propagated one call
edge at a time; nested workflows receive only secrets explicitly forwarded by
their direct caller.

Environment protection is an acquired control-plane fact and cannot be asserted
by the workflow document being analyzed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Collection

from ovk.compilers.github_actions.composite_actions import expand_composite_action
from ovk.compilers.github_actions.expressions import (
    contains_untrusted_context,
    references_github_token,
    references_protected_env,
    secret_names,
)
from ovk.compilers.github_actions.ir import (
    GitHubActionsIR,
    SecretUse,
    TrustEdge,
    TrustFinding,
    TrustNode,
    WorkflowRef,
)
from ovk.compilers.github_actions.loader import load_workflow_file
from ovk.compilers.github_actions.permissions import (
    PermissionCeiling,
    effective_permissions_for_job,
    effective_permissions_under_ceiling,
    extract_permissions,
    job_write_token_risk,
    permission_ceiling_for_job,
)
from ovk.compilers.github_actions.reusable_workflows import parse_uses
from ovk.compilers.github_actions.secrets import extract_secrets

UNTRUSTED_WORKFLOW_CODE_TRIGGERS = frozenset({"pull_request"})
PRIVILEGED_EVENT_TRIGGERS = frozenset({"pull_request_target", "issue_comment", "workflow_run"})
_GENERIC_TOKEN_SECRET = "GITHUB_TOKEN"


def compile_workflow_trust(
    workflow: dict[str, Any],
    *,
    repo_root: Path | None = None,
    protected_environments: Collection[str] | None = None,
    _permission_ceiling: PermissionCeiling | None = None,
    _available_secret_names: frozenset[str] | None = None,
    _event_triggers: frozenset[str] | None = None,
    _visiting: frozenset[str] | None = None,
    _id_prefix: str = "",
    _inherited_untrusted_inputs: bool = False,
) -> GitHubActionsIR:
    """Compile one workflow document into a trust-flow IR.

    Public callers omit the underscored parameters. They are used only while
    recursively compiling local reusable workflows so authority and trust
    context are preserved across call edges.

    ``protected_environments`` must come from a separately trusted acquisition
    path. The workflow payload itself is never allowed to self-assert this fact.
    """
    path = str(workflow.get("_ovk_path") or "workflow.yml")
    workflow_node_id = f"{_id_prefix}workflow:{path}"
    nodes: list[TrustNode] = [TrustNode(node_id=workflow_node_id, kind="workflow", trust="unknown")]
    edges: list[TrustEdge] = []
    findings: list[TrustFinding] = []
    unsupported: list[str] = []
    warnings: list[str] = []

    on = workflow.get("on") or workflow.get(True)
    triggers = frozenset(_event_triggers if _event_triggers is not None else _triggers(on))
    workflow_code_untrusted = bool(triggers & UNTRUSTED_WORKFLOW_CODE_TRIGGERS)
    if workflow_code_untrusted:
        nodes[0].trust = "untrusted"
    elif triggers & PRIVILEGED_EVENT_TRIGGERS:
        nodes[0].trust = "trusted"
    nodes[0].labels.extend(sorted(triggers))

    permissions = extract_permissions(workflow)
    secrets = extract_secrets(workflow)
    protected_environment_names = frozenset(str(item) for item in (protected_environments or ()))

    visiting = set(_visiting or ())
    current_identity = _workflow_identity(path, repo_root=repo_root)
    if current_identity:
        visiting.add(current_identity)

    jobs = workflow.get("jobs") if isinstance(workflow.get("jobs"), dict) else {}
    for job_id, job in sorted(jobs.items()):
        if not isinstance(job, dict):
            unsupported.append(f"job:{job_id}:not_object")
            continue
        job_id_str = str(job_id)
        (
            effective_permissions,
            permission_source,
            write_token,
            write_token_source,
            next_permission_ceiling,
            token_unresolved,
        ) = _job_authority(
            workflow,
            job_id_str,
            triggers=triggers,
            incoming_ceiling=_permission_ceiling,
        )
        if token_unresolved:
            warnings.append(f"job:{job_id}:default_token_permissions_repository_dependent")
            if _permission_ceiling is not None:
                unsupported.append(f"job:{job_id}:reusable_token_permissions_unresolved")

        job_node_id = f"{_id_prefix}job:{job_id}"
        job_node = TrustNode(
            node_id=job_node_id,
            kind="job",
            trust="untrusted" if workflow_code_untrusted else "unknown",
            labels=[],
        )
        if write_token:
            job_node.labels.append("write_token")
        if token_unresolved:
            job_node.labels.append("token_authority_unresolved")
        job_node.labels.append(f"permissions_source:{permission_source}")
        nodes.append(job_node)
        edges.append(TrustEdge(source=workflow_node_id, target=job_node_id, kind="contains_job"))

        environment = job.get("environment")
        environment_name = _environment_name(environment)
        protected_env = bool(environment_name and environment_name in protected_environment_names)
        if environment is not None:
            job_node.labels.append("environment_declared")
        if protected_env:
            job_node.labels.append("protected_env")

        call_ref: WorkflowRef | None = None
        call_node_id: str | None = None
        if isinstance(job.get("uses"), str):
            uses_value = str(job["uses"])
            call_ref = parse_uses(uses_value)
            call_node_id = f"{_id_prefix}uses:{job_id}"
            call_labels = [uses_value, f"permission_ceiling:{next_permission_ceiling.mode}"]
            if job.get("secrets") == "inherit":
                call_labels.append("secrets_inherit")
            nodes.append(
                TrustNode(
                    node_id=call_node_id,
                    kind="reusable_workflow",
                    trust="unknown",
                    labels=call_labels,
                )
            )
            edges.append(TrustEdge(source=job_node_id, target=call_node_id, kind="uses"))
            if call_ref.mutable_ref:
                findings.append(
                    TrustFinding(
                        kind="mutable_remote_ref",
                        summary=f"mutable reusable workflow ref in job {job_id}",
                        node_ids=[job_node_id],
                        evidence={"uses": uses_value},
                    )
                )
            if job.get("secrets") == "inherit":
                findings.append(
                    TrustFinding(
                        kind="secrets_inherit",
                        summary=f"job {job_id} inherits secrets into reusable workflow",
                        node_ids=[job_node_id],
                        evidence={
                            "uses": uses_value,
                            "direct_call_only": True,
                            "resolved_local": not call_ref.remote,
                        },
                    )
                )

        workspace_untrusted = workflow_code_untrusted

        for index, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            step_id = str(step.get("id") or step.get("name") or index)
            step_node_id = f"{_id_prefix}job:{job_id}:step:{step_id}"
            run = str(step.get("run") or "")
            uses = str(step.get("uses") or "")
            with_blob = json.dumps(step.get("with") or {}, sort_keys=True, default=str)
            step_blob = json.dumps(step, sort_keys=True, default=str)

            checkout_taints_workspace = _checkout_loads_untrusted_pr(uses, step, triggers=set(triggers))
            workflow_run_artifact_taints = _downloads_untrusted_workflow_run_artifact(
                uses,
                triggers=set(triggers),
            )
            command_fetches_untrusted = _run_fetches_untrusted_pr(run)
            executes_workspace = bool(run) or uses.startswith("./") or uses.startswith(".\\")
            inherited_input_taint = _inherited_untrusted_inputs and (
                _references_inputs(run) or _references_inputs(with_blob)
            )
            direct_untrusted_input = (
                contains_untrusted_context(run)
                or (contains_untrusted_context(with_blob) and not _is_checkout(uses))
                or inherited_input_taint
            )
            untrusted_code = bool(
                workflow_code_untrusted
                or direct_untrusted_input
                or command_fetches_untrusted
                or (workspace_untrusted and executes_workspace)
            )

            labels = ["run"] if run else (["uses"] if uses else [])
            if workspace_untrusted:
                labels.append("untrusted_workspace")
            if checkout_taints_workspace:
                labels.append("loads_untrusted_pr")
            if inherited_input_taint:
                labels.append("untrusted_reusable_input")
            step_node = TrustNode(
                node_id=step_node_id,
                kind="step",
                trust="untrusted" if untrusted_code else "unknown",
                labels=labels,
            )
            nodes.append(step_node)
            edges.append(TrustEdge(source=job_node_id, target=step_node_id, kind="contains_step"))

            accessible_secret_names = _accessible_secret_names(
                step_blob,
                available=_available_secret_names,
            )
            privileged = bool(step.get("with", {}).get("privileged")) if isinstance(step.get("with"), dict) else False
            token_referenced = references_github_token(step_blob)

            if untrusted_code and accessible_secret_names:
                findings.append(
                    TrustFinding(
                        kind="untrusted_code_with_secret",
                        summary=f"untrusted step {step_id} in job {job_id} uses protected secrets",
                        node_ids=[step_node_id],
                        evidence={"secrets": sorted(accessible_secret_names)},
                    )
                )
            if untrusted_code and write_token:
                findings.append(
                    TrustFinding(
                        kind="untrusted_code_with_write_token",
                        summary=f"untrusted step {step_id} runs with write token permissions",
                        node_ids=[step_node_id],
                        evidence={
                            "permission_source": write_token_source,
                            "effective_permissions": [
                                grant.model_dump(mode="json") for grant in effective_permissions
                            ],
                            "github_token_referenced": token_referenced,
                            "workspace_untrusted": workspace_untrusted,
                        },
                    )
                )
            if untrusted_code and protected_env:
                findings.append(
                    TrustFinding(
                        kind="untrusted_code_with_protected_env",
                        summary=f"untrusted step {step_id} runs in a verified protected environment",
                        node_ids=[step_node_id],
                        evidence={"environment": environment_name},
                    )
                )
            if untrusted_code and (privileged or references_protected_env(run)):
                findings.append(
                    TrustFinding(
                        kind="untrusted_code_with_privileged_capability",
                        summary=f"untrusted step {step_id} has privileged capability",
                        node_ids=[step_node_id],
                    )
                )

            if uses.startswith("./") and repo_root is not None:
                rel = uses.replace("\\", "/")
                if rel.startswith("./"):
                    rel = rel[2:]
                action_path = repo_root / rel
                c_nodes, c_edges, c_secrets, c_unsupported = expand_composite_action(
                    action_path,
                    step_node_id=step_node_id,
                    job_id=job_id_str,
                )
                nodes.extend(c_nodes)
                edges.extend(c_edges)
                secrets.extend(c_secrets)
                unsupported.extend(c_unsupported)

            if checkout_taints_workspace or workflow_run_artifact_taints or command_fetches_untrusted:
                workspace_untrusted = True

        if call_ref is not None and call_node_id is not None:
            _compile_reusable_call(
                workflow=workflow,
                job_id=job_id_str,
                job=job,
                call_ref=call_ref,
                call_node_id=call_node_id,
                repo_root=repo_root,
                protected_environments=protected_environment_names,
                permission_ceiling=next_permission_ceiling,
                available_secret_names=_available_secret_names,
                event_triggers=triggers,
                visiting=frozenset(visiting),
                id_prefix=_id_prefix,
                inherited_untrusted_inputs=_inherited_untrusted_inputs,
                findings=findings,
                unsupported=unsupported,
                warnings=warnings,
                nodes=nodes,
                edges=edges,
                secrets=secrets,
                permissions=permissions,
            )

    unique_findings: list[TrustFinding] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for finding in findings:
        key = (finding.kind, finding.summary, tuple(finding.node_ids))
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)

    workflows = _workflow_refs_from_nodes(path, nodes)
    return GitHubActionsIR(
        workflows=workflows,
        nodes=sorted(nodes, key=lambda item: item.node_id),
        edges=sorted(edges, key=lambda item: (item.source, item.target, item.kind)),
        secrets=secrets,
        permissions=permissions,
        findings=sorted(unique_findings, key=lambda item: (item.kind, item.summary, tuple(item.node_ids))),
        unsupported_constructs=sorted(set(unsupported)),
        warnings=sorted(set(warnings)),
    )


def _job_authority(
    workflow: dict[str, Any],
    job_id: str,
    *,
    triggers: frozenset[str],
    incoming_ceiling: PermissionCeiling | None,
) -> tuple[list[Any], str, bool, str, PermissionCeiling, bool]:
    if incoming_ceiling is None:
        effective, source = effective_permissions_for_job(workflow, job_id)
        write_token, write_source = job_write_token_risk(workflow, job_id, triggers=triggers)
        ceiling = permission_ceiling_for_job(workflow, job_id, triggers=triggers)
        unresolved = source == "default" and write_source == "repository_default_unresolved"
        return effective, source, write_token, write_source, ceiling, unresolved

    effective, source, write_token, ceiling, unresolved = effective_permissions_under_ceiling(
        workflow,
        job_id,
        ceiling=incoming_ceiling,
    )
    return effective, source, write_token, source, ceiling, unresolved


def _compile_reusable_call(
    *,
    workflow: dict[str, Any],
    job_id: str,
    job: dict[str, Any],
    call_ref: WorkflowRef,
    call_node_id: str,
    repo_root: Path | None,
    protected_environments: frozenset[str],
    permission_ceiling: PermissionCeiling,
    available_secret_names: frozenset[str] | None,
    event_triggers: frozenset[str],
    visiting: frozenset[str],
    id_prefix: str,
    inherited_untrusted_inputs: bool,
    findings: list[TrustFinding],
    unsupported: list[str],
    warnings: list[str],
    nodes: list[TrustNode],
    edges: list[TrustEdge],
    secrets: list[SecretUse],
    permissions: list[Any],
) -> None:
    uses_value = str(job.get("uses") or "")
    passed_secrets = _passed_secret_names(job, available=available_secret_names)
    call_with_blob = json.dumps(job.get("with") or {}, sort_keys=True, default=str)
    caller_input_tainted = contains_untrusted_context(call_with_blob) or (
        inherited_untrusted_inputs and _references_inputs(call_with_blob)
    )

    if call_ref.remote:
        if permission_ceiling.mode == "unresolved_default":
            unsupported.append(f"reusable_workflow:{job_id}:token_permissions_unresolved")
        if caller_input_tainted and permission_ceiling.mode != "exact":
            findings.append(
                TrustFinding(
                    kind="review",
                    summary=f"reusable workflow call {job_id} receives untrusted input with unresolved authority",
                    node_ids=[call_node_id],
                    evidence={"uses": uses_value},
                )
            )
        return

    if repo_root is None:
        unsupported.append(f"reusable_workflow:{job_id}:local_resolution_requires_repo_root")
        return

    child_path = _local_reusable_path(repo_root, uses_value)
    if child_path is None:
        findings.append(
            TrustFinding(
                kind="review",
                summary=f"local reusable workflow path escapes repository: {uses_value}",
                node_ids=[call_node_id],
            )
        )
        unsupported.append(f"reusable_workflow:{job_id}:path_escape")
        return
    if not _valid_reusable_location(repo_root, child_path):
        findings.append(
            TrustFinding(
                kind="review",
                summary=f"local reusable workflow is outside .github/workflows: {uses_value}",
                node_ids=[call_node_id],
            )
        )
        unsupported.append(f"reusable_workflow:{job_id}:invalid_location")
        return
    if not child_path.exists():
        findings.append(
            TrustFinding(
                kind="review",
                summary=f"local reusable workflow missing: {uses_value}",
                node_ids=[call_node_id],
            )
        )
        unsupported.append(f"reusable_workflow:{job_id}:missing")
        return

    child_identity = str(child_path.resolve())
    if child_identity in visiting:
        findings.append(
            TrustFinding(
                kind="cycle",
                summary=f"reusable workflow cycle involving {child_identity}",
                node_ids=[call_node_id],
            )
        )
        unsupported.append(f"reusable_workflow:{job_id}:cycle")
        return

    child = load_workflow_file(child_path)
    child["_ovk_path"] = child_path.relative_to(repo_root.resolve()).as_posix()
    child_prefix = f"{id_prefix}reusable:{job_id}:"
    child_ir = compile_workflow_trust(
        child,
        repo_root=repo_root,
        protected_environments=protected_environments,
        _permission_ceiling=permission_ceiling,
        _available_secret_names=passed_secrets,
        _event_triggers=event_triggers,
        _visiting=frozenset(set(visiting) | {child_identity}),
        _id_prefix=child_prefix,
        _inherited_untrusted_inputs=caller_input_tainted,
    )
    nodes.extend(child_ir.nodes)
    edges.extend(child_ir.edges)
    edges.append(
        TrustEdge(
            source=call_node_id,
            target=f"{child_prefix}workflow:{child['_ovk_path']}",
            kind="calls_workflow",
        )
    )
    findings.extend(child_ir.findings)
    unsupported.extend(child_ir.unsupported_constructs)
    warnings.extend(child_ir.warnings)
    secrets.extend(child_ir.secrets)
    permissions.extend(child_ir.permissions)


def _workflow_refs_from_nodes(path: str, nodes: list[TrustNode]) -> list[WorkflowRef]:
    refs = [WorkflowRef(path=path, remote=False)]
    seen = {path}
    for node in nodes:
        if node.kind != "workflow":
            continue
        marker = "workflow:"
        position = node.node_id.rfind(marker)
        if position < 0:
            continue
        child_path = node.node_id[position + len(marker):]
        if child_path in seen:
            continue
        seen.add(child_path)
        refs.append(WorkflowRef(path=child_path, remote=False))
    return refs


def _workflow_identity(path: str, *, repo_root: Path | None) -> str | None:
    if repo_root is None:
        return None
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    try:
        return str(candidate.resolve())
    except OSError:
        return None


def _local_reusable_path(repo_root: Path, uses: str) -> Path | None:
    root = repo_root.resolve()
    rel = uses.replace("\\", "/")
    if rel.startswith("./"):
        rel = rel[2:]
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def _valid_reusable_location(repo_root: Path, path: Path) -> bool:
    try:
        rel = path.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return False
    return rel.parent.as_posix() == ".github/workflows"


def _passed_secret_names(
    job: dict[str, Any],
    *,
    available: frozenset[str] | None,
) -> frozenset[str] | None:
    block = job.get("secrets")
    if block == "inherit":
        return available
    if not isinstance(block, dict):
        return frozenset()

    passed: set[str] = set()
    for target, expression in block.items():
        sources = {
            name
            for name in secret_names(str(expression))
            if name != _GENERIC_TOKEN_SECRET
        }
        token_source = references_github_token(str(expression))
        if sources:
            if available is None or any(name in available for name in sources):
                passed.add(str(target))
        elif token_source:
            passed.add(str(target))
    return frozenset(passed)


def _accessible_secret_names(
    text: str,
    *,
    available: frozenset[str] | None,
) -> set[str]:
    names = {
        name
        for name in secret_names(text)
        if name != _GENERIC_TOKEN_SECRET
    }
    if available is None:
        return names
    return {name for name in names if name in available}


def _references_inputs(text: str) -> bool:
    return "inputs." in (text or "").lower()


def _environment_name(environment: Any) -> str | None:
    if isinstance(environment, str):
        return environment
    if isinstance(environment, dict) and environment.get("name") is not None:
        return str(environment.get("name"))
    return None


def _is_checkout(uses: str) -> bool:
    return uses.strip().lower().startswith("actions/checkout@")


def _checkout_loads_untrusted_pr(
    uses: str,
    step: dict[str, Any],
    *,
    triggers: set[str],
) -> bool:
    if not _is_checkout(uses):
        return False
    if "pull_request_target" not in triggers and "issue_comment" not in triggers:
        return False
    with_block = step.get("with") if isinstance(step.get("with"), dict) else {}
    blob = json.dumps(with_block, sort_keys=True, default=str).lower()
    markers = (
        "github.event.pull_request.head.sha",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.repo.full_name",
        "github.head_ref",
        "github.event.pull_request.merge_commit_sha",
        "refs/pull/",
    )
    return any(marker in blob for marker in markers)


def _downloads_untrusted_workflow_run_artifact(uses: str, *, triggers: set[str]) -> bool:
    return "workflow_run" in triggers and uses.strip().lower().startswith("actions/download-artifact@")


def _run_fetches_untrusted_pr(run: str) -> bool:
    blob = (run or "").lower()
    if not blob:
        return False
    fetch_like = "git fetch" in blob or "gh pr checkout" in blob or "refs/pull/" in blob
    return fetch_like and (
        "github.event.pull_request" in blob
        or "github.head_ref" in blob
        or "refs/pull/" in blob
        or "gh pr checkout" in blob
    )


def _triggers(on: Any) -> set[str]:
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(item) for item in on}
    if isinstance(on, dict):
        return {str(key) for key in on}
    return set()
