"""Deterministic CI secrets exposure checker."""

from __future__ import annotations

from typing import Any

FAILURE_MODE = "secrets_exposed_in_untrusted_context"
UNTRUSTED_TRIGGERS = frozenset({"pull_request", "pull_request_target", "issue_comment"})
SECRET_MARKERS = ("secrets.", "secrets[", "${{ secrets")


def _workflows(data: dict[str, Any]) -> list[dict[str, Any]]:
    workflows = data.get("workflows", [])
    return [item for item in workflows if isinstance(item, dict)]


def _uses_secrets(workflow: dict[str, Any]) -> bool:
    if workflow.get("uses_secrets") is True:
        return True
    serialized = str(workflow)
    return any(marker in serialized for marker in SECRET_MARKERS)


def _untrusted_trigger(workflow: dict[str, Any]) -> bool:
    triggers = workflow.get("triggers", [])
    if not isinstance(triggers, list):
        return False
    return any(str(trigger) in UNTRUSTED_TRIGGERS for trigger in triggers)


def find_ci_secrets_counterexamples(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Find workflows that expose secrets in untrusted contexts."""
    counterexamples: list[dict[str, Any]] = []
    trust_context = str(data.get("trust_context", "untrusted_fork_pr"))
    # Trust-flow compiler findings participate in enforcement when present.
    findings = data.get("trust_findings")
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            kind = str(finding.get("kind") or "")
            if kind in {
                "untrusted_code_with_secret",
                "untrusted_code_with_write_token",
                "untrusted_code_with_protected_env",
                "untrusted_code_with_privileged_capability",
                "secrets_inherit",
            }:
                counterexamples.append(
                    {
                        "summary": str(finding.get("summary") or kind),
                        "failure_mode": FAILURE_MODE,
                        "workflow_id": ",".join(str(item) for item in finding.get("node_ids") or [])
                        or "trust-flow",
                        "triggers": [],
                        "trust_context": trust_context,
                        "trust_finding_kind": kind,
                    }
                )
    for workflow in _workflows(data):
        workflow_id = str(workflow.get("workflow_id", "unknown"))
        if trust_context.startswith("untrusted") and _untrusted_trigger(workflow) and _uses_secrets(workflow):
            counterexamples.append(
                {
                    "summary": f"Workflow {workflow_id} references secrets on an untrusted trigger.",
                    "failure_mode": FAILURE_MODE,
                    "workflow_id": workflow_id,
                    "triggers": workflow.get("triggers", []),
                    "trust_context": trust_context,
                }
            )
        if workflow.get("pull_request_target_with_pr_head_checkout") and _uses_secrets(workflow):
            counterexamples.append(
                {
                    "summary": f"Workflow {workflow_id} uses pull_request_target with PR head checkout and secrets.",
                    "failure_mode": FAILURE_MODE,
                    "workflow_id": workflow_id,
                    "triggers": workflow.get("triggers", []),
                    "trust_context": trust_context,
                }
            )
    return counterexamples
