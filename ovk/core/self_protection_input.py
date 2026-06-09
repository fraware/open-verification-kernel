"""Structured input builder for the Sprint 1 self-protection path."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ovk.adapters.opa.self_protection import DEFAULT_GATE_NAME


@dataclass(frozen=True)
class SelfProtectionMetadata:
    """Metadata needed to evaluate the self-protection intent."""

    actor_type: str = "ai_agent"
    agent_id: str = "unknown"
    task: str = "unknown"
    changed_files: list[str] = field(default_factory=list)
    before_required_checks: list[str] | None = None
    after_required_checks: list[str] | None = None
    before_workflow_permissions: dict[str, str] | None = None
    after_workflow_permissions: dict[str, str] | None = None
    ovk_gate_name: str = DEFAULT_GATE_NAME


def build_self_protection_input(metadata: SelfProtectionMetadata) -> dict[str, Any]:
    """Build the canonical input object for the self-protection adapter.

    Required-check metadata is intentionally optional. If a high-risk change lacks
    the before or after required-check set, the adapter must return unknown.
    """
    payload: dict[str, Any] = {
        "actor": {
            "type": metadata.actor_type,
            "id": metadata.agent_id,
        },
        "task": metadata.task,
        "ovk_gate_name": metadata.ovk_gate_name,
        "changed_files": metadata.changed_files,
        "before": {},
        "after": {},
    }

    if metadata.before_required_checks is not None:
        payload["before"]["required_checks"] = metadata.before_required_checks
    if metadata.after_required_checks is not None:
        payload["after"]["required_checks"] = metadata.after_required_checks
    if metadata.before_workflow_permissions is not None:
        payload["before"]["workflow_permissions"] = metadata.before_workflow_permissions
    if metadata.after_workflow_permissions is not None:
        payload["after"]["workflow_permissions"] = metadata.after_workflow_permissions

    return payload


def build_from_json_like(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize a JSON-like metadata object into canonical adapter input."""
    metadata = SelfProtectionMetadata(
        actor_type=str(data.get("actor_type", data.get("author_type", "ai_agent"))),
        agent_id=str(data.get("agent_id", data.get("agent", "unknown"))),
        task=str(data.get("task", "unknown")),
        changed_files=[str(path) for path in data.get("changed_files", [])],
        before_required_checks=data.get("before_required_checks"),
        after_required_checks=data.get("after_required_checks"),
        before_workflow_permissions=data.get("before_workflow_permissions"),
        after_workflow_permissions=data.get("after_workflow_permissions"),
        ovk_gate_name=str(data.get("ovk_gate_name", DEFAULT_GATE_NAME)),
    )
    return build_self_protection_input(metadata)
