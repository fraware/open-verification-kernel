"""Verification planning from changed files.

The planner joins change-surface detection, intent-template loading, capability
manifests, and backend routing. It is the first kernel-level orchestration step
above individual adapters.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ovk.adapters.workflow.diff_extract import workflow_inputs_from_diff
from ovk.core.capabilities import CapabilityRegistry
from ovk.core.change_detection import detect_change_surfaces, infer_candidate_intents
from ovk.core.diff_parser import extract_changed_paths, is_unified_diff
from ovk.core.intent_registry import IntentRegistry
from ovk.core.router import route_intent


def plan_from_changed_files(
    changed_files: list[str],
    *,
    template_dir: Path = Path("templates"),
    adapter_dir: Path = Path("adapters"),
) -> dict[str, Any]:
    """Create a verification plan from changed file paths."""
    intent_registry = IntentRegistry.from_directory(template_dir)
    capability_registry = CapabilityRegistry.from_directory(adapter_dir)
    candidate_ids = infer_candidate_intents(changed_files)

    intent_plans: list[dict[str, Any]] = []
    missing_intents: list[str] = []
    for intent_id in candidate_ids:
        intent = intent_registry.get(intent_id)
        if intent is None:
            missing_intents.append(intent_id)
            continue
        intent_plans.append(
            {
                "intent_id": intent_id,
                "intent": intent,
                "routing": route_intent(intent, capability_registry.all()),
            }
        )

    return {
        "changed_files": changed_files,
        "surfaces": [surface.__dict__ for surface in detect_change_surfaces(changed_files)],
        "candidate_intents": candidate_ids,
        "intent_plans": intent_plans,
        "missing_intents": missing_intents,
    }


def plan_from_diff_text(
    diff_text: str,
    *,
    template_dir: Path = Path("templates"),
    adapter_dir: Path = Path("adapters"),
    trust_context: str = "untrusted_fork_pr",
) -> dict[str, Any]:
    """Create a verification plan from unified diff text.

    In addition to path-based intent routing, workflow files in the diff are
    parsed into CI secrets lane inputs so agents can verify PR patches directly.
    """
    if not is_unified_diff(diff_text):
        raise ValueError("input is not a unified diff")
    changed_files = extract_changed_paths(diff_text)
    plan = plan_from_changed_files(changed_files, template_dir=template_dir, adapter_dir=adapter_dir)
    workflow_inputs = workflow_inputs_from_diff(diff_text, trust_context=trust_context)
    plan["source"] = "unified_diff"
    plan["workflow_inputs"] = workflow_inputs
    if workflow_inputs:
        plan["suggested_lane_inputs"] = {"ci_secrets": workflow_inputs}
    return plan
