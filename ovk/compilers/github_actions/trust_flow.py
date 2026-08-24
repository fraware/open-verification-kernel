"""Trust-flow analysis for GitHub Actions workflows.

Property: untrusted code executing with a protected secret, write token,
protected environment, or privileged capability is a finding.

Token authority is evaluated per job. Workflow-level and job-level permission
blocks are not unioned across principals, and merely referencing GITHUB_TOKEN
does not imply that the token has write authority.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ovk.compilers.github_actions.composite_actions import expand_composite_action
from ovk.compilers.github_actions.expressions import (
    contains_untrusted_context,
    references_github_token,
    references_protected_env,
)
from ovk.compilers.github_actions.ir import (
    GitHubActionsIR,
    TrustEdge,
    TrustFinding,
    TrustNode,
    WorkflowRef,
)
from ovk.compilers.github_actions.permissions import (
    effective_permissions_for_job,
    extract_permissions,
    job_write_token_risk,
)
from ovk.compilers.github_actions.reusable_workflows import parse_uses, resolve_local_reusable
from ovk.compilers.github_actions.secrets import extract_secrets

UNTRUSTED_TRIGGERS = frozenset({"pull_request_target", "pull_request", "issue_comment", "workflow_run"})


def compile_workflow_trust(
    workflow: dict[str, Any],
    *,
    repo_root: Path | None = None,
) -> GitHubActionsIR:
    """Compile one workflow document into a trust-flow IR."""
    path = str(workflow.get("_ovk_path") or "workflow.yml")
    nodes: list[TrustNode] = [TrustNode(node_id=f"workflow:{path}", kind="workflow", trust="unknown")]
    edges: list[TrustEdge] = []
    findings: list[TrustFinding] = []
    unsupported: list[str] = []
    warnings: list[str] = []

    on = workflow.get("on") or workflow.get(True)
    triggers = _triggers(on)
    untrusted_trigger = any(trigger in UNTRUSTED_TRIGGERS for trigger in triggers)
    if untrusted_trigger:
        nodes[0].trust = "untrusted"
        nodes[0].labels.extend(sorted(triggers))

    # Keep the declaration inventory in the IR, but never use this global list
    # to decide one job's effective authority.
    permissions = extract_permissions(workflow)
    secrets = extract_secrets(workflow)

    jobs = workflow.get("jobs") if isinstance(workflow.get("jobs"), dict) else {}
    for job_id, job in sorted(jobs.items()):
        if not isinstance(job, dict):
            unsupported.append(f"job:{job_id}:not_object")
            continue
        job_id_str = str(job_id)
        effective_permissions, permission_source = effective_permissions_for_job(workflow, job_id_str)
        write_token, write_token_source = job_write_token_risk(
            workflow,
            job_id_str,
            triggers=triggers,
        )
        if permission_source == "default" and write_token_source == "repository_default_unresolved":
            warnings.append(
                f"job:{job_id}:default_token_permissions_repository_dependent"
            )

        job_node = TrustNode(
            node_id=f"job:{job_id}",
            kind="job",
            trust="untrusted" if untrusted_trigger else "unknown",
            labels=[],
        )
        if write_token:
            job_node.labels.append("write_token")
        job_node.labels.append(f"permissions_source:{permission_source}")
        nodes.append(job_node)
        edges.append(TrustEdge(source=nodes[0].node_id, target=job_node.node_id, kind="contains_job"))

        environment = job.get("environment")
        protected_env = _environment_is_protected(workflow, environment)
        if environment is not None:
            job_node.labels.append("environment_declared")
        if protected_env:
            job_node.labels.append("protected_env")

        if isinstance(job.get("uses"), str):
            ref = parse_uses(str(job["uses"]))
            nodes.append(
                TrustNode(
                    node_id=f"uses:{job_id}",
                    kind="reusable_workflow",
                    trust="unknown",
                    labels=[str(job["uses"])],
                )
            )
            edges.append(TrustEdge(source=job_node.node_id, target=f"uses:{job_id}", kind="uses"))
            if ref.mutable_ref:
                findings.append(
                    TrustFinding(
                        kind="mutable_remote_ref",
                        summary=f"mutable reusable workflow ref in job {job_id}",
                        node_ids=[job_node.node_id],
                        evidence={"uses": job["uses"]},
                    )
                )

        for index, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            step_id = str(step.get("id") or step.get("name") or index)
            step_node_id = f"job:{job_id}:step:{step_id}"
            run = str(step.get("run") or "")
            uses = str(step.get("uses") or "")
            step_blob = json.dumps(step, sort_keys=True, default=str)
            untrusted_code = (
                untrusted_trigger
                or contains_untrusted_context(run)
                or contains_untrusted_context(str(step.get("with") or ""))
            )
            step_node = TrustNode(
                node_id=step_node_id,
                kind="step",
                trust="untrusted" if untrusted_code else "unknown",
                labels=["run"] if run else (["uses"] if uses else []),
            )
            nodes.append(step_node)
            edges.append(TrustEdge(source=job_node.node_id, target=step_node_id, kind="contains_step"))

            step_secrets = [
                item
                for item in secrets
                if item.job_id == job_id_str and item.step_id in {step_id, None}
            ]
            privileged = bool(step.get("with", {}).get("privileged")) if isinstance(step.get("with"), dict) else False
            token_referenced = references_github_token(step_blob)

            if untrusted_code and step_secrets:
                findings.append(
                    TrustFinding(
                        kind="untrusted_code_with_secret",
                        summary=f"untrusted step {step_id} in job {job_id} uses protected secrets",
                        node_ids=[step_node_id],
                        evidence={"secrets": [item.name for item in step_secrets]},
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
                        },
                    )
                )
            if untrusted_code and protected_env:
                findings.append(
                    TrustFinding(
                        kind="untrusted_code_with_protected_env",
                        summary=f"untrusted step {step_id} runs in a verified protected environment",
                        node_ids=[step_node_id],
                        evidence={"environment": _environment_name(environment)},
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

    workflows = [WorkflowRef(path=path, remote=False)]
    if repo_root is not None:
        reusable, reusable_findings = resolve_local_reusable(workflow, repo_root=repo_root)
        findings.extend(reusable_findings)
        for child in reusable:
            child_path = str(child.get("_ovk_path") or "reusable.yml")
            nodes.append(TrustNode(node_id=f"workflow:{child_path}", kind="reusable_workflow_doc", trust="unknown"))
            child_secrets = extract_secrets(child)
            child_permissions = extract_permissions(child)
            secrets.extend(child_secrets)
            permissions.extend(child_permissions)
            workflows.append(WorkflowRef(path=child_path, remote=False))

    unique_findings = []
    seen = set()
    for finding in findings:
        key = (finding.kind, finding.summary)
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)

    return GitHubActionsIR(
        workflows=workflows,
        nodes=sorted(nodes, key=lambda item: item.node_id),
        edges=sorted(edges, key=lambda item: (item.source, item.target, item.kind)),
        secrets=secrets,
        permissions=permissions,
        findings=sorted(unique_findings, key=lambda item: (item.kind, item.summary)),
        unsupported_constructs=sorted(set(unsupported)),
        warnings=sorted(set(warnings)),
    )


def _environment_name(environment: Any) -> str | None:
    if isinstance(environment, str):
        return environment
    if isinstance(environment, dict) and environment.get("name") is not None:
        return str(environment.get("name"))
    return None


def _environment_is_protected(workflow: dict[str, Any], environment: Any) -> bool:
    """Return protection only from acquired environment metadata, never syntax alone.

    ``jobs.<id>.environment`` merely selects an environment; it does not prove
    that required reviewers, wait timers or other protection rules exist. A
    source collector may provide ``_ovk_protected_environments`` as a list of
    environment names after trusted acquisition. Absence of that metadata is
    deliberately non-authorizing.
    """
    name = _environment_name(environment)
    if not name:
        return False
    raw = workflow.get("_ovk_protected_environments")
    if not isinstance(raw, list):
        return False
    return name in {str(item) for item in raw}


def _triggers(on: Any) -> set[str]:
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(item) for item in on}
    if isinstance(on, dict):
        return {str(key) for key in on}
    return set()
