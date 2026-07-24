"""Compile lane-specific inputs from verification plans."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ovk.adapters.cbmc.diff_extract import cbmc_inputs_from_diff
from ovk.adapters.deployment.diff_extract import deployment_inputs_from_diff
from ovk.adapters.workflow.diff_extract import workflow_inputs_from_diff
from ovk.adapters.z3.route_extract import authorization_inputs_from_diff
from ovk.core.diff_iac import infra_inputs_from_diff
from ovk.core.diff_parser import is_unified_diff
from ovk.core.multi_lane import normalize_lane_name
from ovk.core.planner import plan_from_changed_files, plan_from_diff_text
from ovk.core.sprint1_runner import build_metadata_from_inputs


INTENT_TO_LANE = {
    "agent-cannot-disable-own-ci-gate": "self_protection",
    "no-admin-route-bypass": "authorization",
    "no-public-sensitive-resource": "infrastructure",
    "no-secrets-in-untrusted-context": "ci_secrets",
    "no-skipped-approval-state": "deployment",
    "cbmc-harness-check": "backend",
    "cbmc-buffer-bounds": "backend",
    "cbmc-no-integer-overflow-quota": "backend",
    "cbmc-no-unchecked-buffer-copy": "backend",
    "cbmc-no-use-after-free-auth-cache": "backend",
}


def compile_lane_inputs_from_plan(
    plan: dict[str, Any],
    *,
    diff_text: str | None = None,
    metadata: dict[str, Any] | None = None,
    check_metadata_path: Path | None = None,
    github_event_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Compile executable lane jobs from a planner payload."""
    jobs: list[dict[str, Any]] = []
    intents = plan.get("candidate_intents", [])
    lanes_needed = {INTENT_TO_LANE.get(intent, normalize_lane_name(intent)) for intent in intents}

    if "self_protection" in lanes_needed:
        meta = dict(metadata or {})
        if github_event_path or check_metadata_path:
            meta = build_metadata_from_inputs(
                metadata_path=None,
                changed_files_path=None,
                check_metadata_path=check_metadata_path,
                github_event_path=github_event_path,
            )
            meta.setdefault("changed_files", plan.get("changed_files", []))
        elif not meta.get("changed_files"):
            meta["changed_files"] = plan.get("changed_files", [])
        jobs.append({"lane": "self_protection", "data": meta, "input_format": "infra"})

    if diff_text and is_unified_diff(diff_text):
        if "ci_secrets" in lanes_needed:
            for index, data in enumerate(workflow_inputs_from_diff(diff_text)):
                jobs.append(
                    {"lane": "ci_secrets", "data": data, "input_format": "infra", "job_id": f"ci_secrets_{index}"}
                )
        if "authorization" in lanes_needed:
            for index, data in enumerate(authorization_inputs_from_diff(diff_text)):
                jobs.append(
                    {"lane": "authorization", "data": data, "input_format": "infra", "job_id": f"authorization_{index}"}
                )
        if "infrastructure" in lanes_needed:
            for index, item in enumerate(infra_inputs_from_diff(diff_text)):
                jobs.append(
                    {
                        "lane": "infrastructure",
                        "data": item["data"],
                        "input_format": item["input_format"],
                        "job_id": f"infrastructure_{index}",
                    }
                )
        if "deployment" in lanes_needed:
            for index, data in enumerate(deployment_inputs_from_diff(diff_text)):
                jobs.append(
                    {"lane": "deployment", "data": data, "input_format": "infra", "job_id": f"deployment_{index}"}
                )
        if "backend" in lanes_needed:
            candidate_intents = set(plan.get("candidate_intents", []))
            for index, data in enumerate(cbmc_inputs_from_diff(diff_text)):
                intent_id = str(data.get("intent_id", ""))
                if intent_id not in candidate_intents:
                    continue
                jobs.append(
                    {
                        "lane": "backend",
                        "data": data,
                        "input_format": "backend",
                        "job_id": f"cbmc_{index}",
                        "intent_id": intent_id,
                    }
                )

    suggested = plan.get("suggested_lane_inputs", {})
    if isinstance(suggested.get("ci_secrets"), list):
        existing = sum(1 for job in jobs if job["lane"] == "ci_secrets")
        for index, data in enumerate(suggested["ci_secrets"][existing:]):
            jobs.append(
                {"lane": "ci_secrets", "data": data, "input_format": "infra", "job_id": f"ci_secrets_suggested_{index}"}
            )

    return jobs


def build_plan_from_inputs(
    *,
    changed_files: list[str] | None = None,
    diff_text: str | None = None,
) -> dict[str, Any]:
    """Build a planner payload from changed paths or diff text."""
    if diff_text and is_unified_diff(diff_text):
        return plan_from_diff_text(diff_text)
    return plan_from_changed_files(changed_files or [])
