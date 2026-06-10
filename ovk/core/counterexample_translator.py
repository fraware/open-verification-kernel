"""Translate counterexamples into regression artifacts and repair hints."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from ovk.adapters.ci_secrets.regression import render_ci_secrets_regression_suite
from ovk.adapters.deployment.regression import render_deployment_regression_suite
from ovk.adapters.infra.regression import render_infra_regression_suite
from ovk.adapters.z3.regression import render_authorization_regression_suite
from ovk.core.models import EvidenceBundle


FAILURE_MODE_TO_LANE: dict[str, str] = {
    "admin_route_reachable_by_non_admin": "authorization",
    "authorization_abstraction_invalid": "authorization",
    "sensitive_resource_publicly_exposed": "infrastructure",
    "infrastructure_abstraction_invalid": "infrastructure",
    "secrets_exposed_in_untrusted_context": "ci_secrets",
    "required_check_removed": "self_protection",
    "missing_required_metadata": "self_protection",
    "verification_config_changed_by_agent": "self_protection",
    "skipped_required_approval_state": "deployment",
    "opa_policy_violation": "self_protection",
}

FIX_CLASSES: dict[str, str] = {
    "required_check_removed": "restore_ci_gate",
    "secrets_exposed_in_untrusted_context": "remove_untrusted_secret_usage",
    "sensitive_resource_publicly_exposed": "restrict_public_access",
    "admin_route_reachable_by_non_admin": "add_route_guard",
    "skipped_required_approval_state": "add_approval_transition",
    "missing_state_machine_abstraction": "add_approval_transition",
    "missing_required_metadata": "add_required_metadata",
    "verification_config_changed_by_agent": "revert_agent_config_change",
    "authorization_abstraction_invalid": "fix_authorization_input",
    "infrastructure_abstraction_invalid": "fix_infrastructure_input",
    "opa_policy_violation": "fix_policy_violation",
}

REPAIR_SUGGESTIONS: dict[str, str] = {
    "required_check_removed": "Restore the removed required CI check before merge.",
    "secrets_exposed_in_untrusted_context": "Remove secret references from untrusted workflow triggers.",
    "sensitive_resource_publicly_exposed": "Restrict public access on the sensitive resource.",
    "admin_route_reachable_by_non_admin": "Block non-admin reachability to admin routes.",
    "skipped_required_approval_state": "Add the missing approval transition in the deployment state machine.",
    "missing_state_machine_abstraction": "Provide a complete deployment state machine with required approvals.",
    "missing_required_metadata": "Provide required check metadata for self-protection evaluation.",
    "verification_config_changed_by_agent": "Revert agent-authored verification configuration changes.",
    "authorization_abstraction_invalid": "Repair the authorization abstraction input.",
    "infrastructure_abstraction_invalid": "Repair the infrastructure abstraction input.",
    "opa_policy_violation": "Resolve the policy violation reported by OPA.",
}

LANE_RENDERERS: dict[str, Callable[[list[dict[str, Any]]], str]] = {
    "authorization": render_authorization_regression_suite,
    "infrastructure": render_infra_regression_suite,
    "ci_secrets": render_ci_secrets_regression_suite,
    "deployment": render_deployment_regression_suite,
}


def lane_for_counterexample(counterexample: dict[str, Any], *, intent_id: str = "unknown") -> str:
    """Infer the verification lane for a counterexample."""
    failure_mode = str(counterexample.get("failure_mode", "unknown"))
    if failure_mode in FAILURE_MODE_TO_LANE:
        return FAILURE_MODE_TO_LANE[failure_mode]
    if "route" in counterexample or "user_role" in counterexample:
        return "authorization"
    if "resource_id" in counterexample and "sensitivity" in counterexample:
        return "infrastructure"
    if "workflow_id" in counterexample:
        return "ci_secrets"
    if "skipped_required_states" in counterexample:
        return "deployment"
    return intent_id


def regression_artifact_for_counterexample(counterexample: dict[str, Any], *, lane: str) -> dict[str, Any]:
    """Build a regression artifact payload from a counterexample."""
    return {
        "schema_version": "ovk.regression.v1",
        "lane": lane,
        "failure_mode": counterexample.get("failure_mode", "unknown"),
        "summary": counterexample.get("summary", ""),
        "fixture": counterexample,
    }


def repair_hint_for_counterexample(counterexample: dict[str, Any]) -> dict[str, Any]:
    """Build a machine-readable repair hint from a counterexample."""
    failure_mode = str(counterexample.get("failure_mode", "unknown"))
    affected_file = counterexample.get("affected_file") or counterexample.get("source_path")
    line_hunk = counterexample.get("line_hunk") or counterexample.get("line")
    fix_class = FIX_CLASSES.get(failure_mode, "review_counterexample")
    suggested_action = REPAIR_SUGGESTIONS.get(
        failure_mode,
        "Review the counterexample and apply a targeted fix.",
    )
    repair_plan = {
        "failure_mode": failure_mode,
        "fix_class": fix_class,
        "suggested_action": suggested_action,
        "summary": counterexample.get("summary", ""),
    }
    if affected_file:
        repair_plan["affected_file"] = affected_file
    if line_hunk is not None:
        repair_plan["line_hunk"] = line_hunk
    return repair_plan


def render_regression_pytest(counterexample: dict[str, Any], *, lane: str) -> str | None:
    """Render an executable pytest snippet for one counterexample when supported."""
    renderer = LANE_RENDERERS.get(lane)
    if renderer is None:
        return None
    return renderer([counterexample])


def generate_regression_artifacts(bundle: EvidenceBundle) -> list[dict[str, Any]]:
    """Generate regression artifacts for all counterexamples in a bundle."""
    artifacts: list[dict[str, Any]] = []
    for evidence in bundle.evidence:
        intent_id = str(evidence.intent.get("intent_id", "unknown"))
        for counterexample in evidence.counterexamples:
            lane = lane_for_counterexample(counterexample, intent_id=intent_id)
            artifact = regression_artifact_for_counterexample(counterexample, lane=lane)
            pytest_source = render_regression_pytest(counterexample, lane=lane)
            if pytest_source:
                artifact["pytest_source"] = pytest_source
            artifacts.append(artifact)
    return artifacts


def write_generated_tests(bundle: EvidenceBundle, output_dir: Path) -> list[Path]:
    """Write regression JSON and pytest artifacts under `.verification/generated_tests/`."""
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for index, artifact in enumerate(generate_regression_artifacts(bundle)):
        failure_mode = str(artifact["failure_mode"])
        json_path = output_dir / f"regression_{index}_{failure_mode}.json"
        json_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        written.append(json_path)
        pytest_source = artifact.get("pytest_source")
        if pytest_source:
            py_path = output_dir / f"regression_{index}_{failure_mode}.py"
            py_path.write_text(pytest_source, encoding="utf-8")
            written.append(py_path)
    return written
