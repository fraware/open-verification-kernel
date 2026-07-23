"""Translate counterexamples into regression artifacts and repair hints."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from ovk.adapters.ci_secrets.regression import render_ci_secrets_regression_suite
from ovk.adapters.deployment.regression import render_deployment_regression_suite
from ovk.adapters.infra.regression import render_infra_regression_suite
from ovk.adapters.z3.minimize import minimize_counterexample
from ovk.adapters.z3.regression import render_authorization_regression_suite
from ovk.core.models import EvidenceBundle


FAILURE_MODE_TO_LANE: dict[str, str] = {
    "admin_route_reachable_by_non_admin": "authorization",
    "authorization_abstraction_invalid": "authorization",
    "privilege_escalation": "authorization",
    "sensitive_resource_publicly_exposed": "infrastructure",
    "infrastructure_abstraction_invalid": "infrastructure",
    "secrets_exposed_in_untrusted_context": "ci_secrets",
    "required_check_removed": "self_protection",
    "missing_required_metadata": "self_protection",
    "verification_config_changed_by_agent": "self_protection",
    "required_approval_state_skipped": "deployment",
    "skipped_required_approval_state": "deployment",
    "opa_policy_violation": "self_protection",
    "cbmc_assertion_failed": "backend",
    "buffer_overflow": "backend",
    "unchecked_memcpy": "backend",
    "use_after_free": "backend",
    "signed_overflow": "backend",
}

FIX_CLASSES: dict[str, str] = {
    "required_check_removed": "restore_ci_gate",
    "secrets_exposed_in_untrusted_context": "remove_untrusted_secret_usage",
    "sensitive_resource_publicly_exposed": "restrict_public_access",
    "admin_route_reachable_by_non_admin": "add_route_guard",
    "privilege_escalation": "revoke_privileged_grant",
    "required_approval_state_skipped": "add_approval_transition",
    "skipped_required_approval_state": "add_approval_transition",
    "missing_state_machine_abstraction": "add_approval_transition",
    "missing_required_metadata": "add_required_metadata",
    "verification_config_changed_by_agent": "revert_agent_config_change",
    "authorization_abstraction_invalid": "fix_authorization_input",
    "infrastructure_abstraction_invalid": "fix_infrastructure_input",
    "opa_policy_violation": "fix_policy_violation",
    "cbmc_assertion_failed": "review_cbmc_counterexample",
    "buffer_overflow": "add_buffer_bounds_check",
    "unchecked_memcpy": "add_copy_length_guard",
    "use_after_free": "fix_memory_lifetime",
    "signed_overflow": "harden_quota_arithmetic",
}

REPAIR_SUGGESTIONS: dict[str, str] = {
    "required_check_removed": "Restore the removed required CI check before merge.",
    "secrets_exposed_in_untrusted_context": "Remove secret references from untrusted workflow triggers.",
    "sensitive_resource_publicly_exposed": "Restrict public access on the sensitive resource.",
    "admin_route_reachable_by_non_admin": "Block non-admin reachability to admin routes.",
    "privilege_escalation": "Revoke newly granted privileged roles or restore least-privilege assignments.",
    "required_approval_state_skipped": "Add the missing approval transition in the deployment state machine.",
    "skipped_required_approval_state": "Add the missing approval transition in the deployment state machine.",
    "missing_state_machine_abstraction": "Provide a complete deployment state machine with required approvals.",
    "missing_required_metadata": "Provide required check metadata for self-protection evaluation.",
    "verification_config_changed_by_agent": "Revert agent-authored verification configuration changes.",
    "authorization_abstraction_invalid": "Repair the authorization abstraction input.",
    "infrastructure_abstraction_invalid": "Repair the infrastructure abstraction input.",
    "opa_policy_violation": "Resolve the policy violation reported by OPA.",
    "cbmc_assertion_failed": "Review the CBMC counterexample trace and repair the reported C property violation.",
    "buffer_overflow": "Add or restore bounds checks on sensitive buffer accesses.",
    "unchecked_memcpy": "Guard memory copy length before copying untrusted input.",
    "use_after_free": "Ensure authentication cache entries are not accessed after free.",
    "signed_overflow": "Use overflow-safe arithmetic for quota and rate-limit counters.",
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
    minimized = minimize_counterexample(counterexample)
    return {
        "schema_version": "ovk.regression.v1",
        "lane": lane,
        "failure_mode": minimized.get("failure_mode", "unknown"),
        "summary": minimized.get("summary", ""),
        "fixture": minimized,
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
        "lane": lane_for_counterexample(counterexample),
    }
    if affected_file:
        repair_plan["affected_file"] = affected_file
    if line_hunk is not None:
        repair_plan["line_hunk"] = line_hunk
    route = counterexample.get("route")
    if route:
        repair_plan["route"] = route
        if not affected_file:
            repair_plan["affected_file"] = f"src/routes/{str(route).strip('/').split('/')[0]}.ts"
    resource_id = counterexample.get("resource_id")
    if resource_id:
        repair_plan["resource_id"] = resource_id
    workflow_id = counterexample.get("workflow_id")
    if workflow_id:
        repair_plan["workflow_id"] = workflow_id
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


def write_generated_tests(
    bundle: EvidenceBundle,
    output_dir: Path,
    *,
    allow_auto_exec: bool = False,
) -> list[Path]:
    """Write regression JSON and pytest artifacts under a constrained output directory.

    Path safety:
    * Rejects ``..`` components in the requested path.
    * Allows workspace-relative paths and standard OS temp directories (pytest
      ``tmp_path``, CI scratch). Arbitrary absolute paths outside those roots
      are rejected.
    * Generated pytest files are artifacts only. They are never executed by
      this function. ``allow_auto_exec`` is reserved for a future policy hook
      and currently must remain false (raising if true) so CI cannot silently
      opt into auto-execution of generated tests.
    """
    import tempfile

    if allow_auto_exec:
        raise ValueError(
            "auto-execution of generated regression tests is disabled; "
            "set allow_auto_exec=False and run pytest explicitly under policy"
        )
    if ".." in Path(output_dir).parts:
        raise ValueError(f"refusing path traversal in generated test output: {output_dir}")

    resolved = output_dir.expanduser().resolve()
    cwd = Path.cwd().resolve()
    verification_root = (cwd / ".verification").resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()

    def _under(root: Path) -> bool:
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            return False

    if not (_under(cwd) or _under(verification_root) or _under(temp_root)):
        raise ValueError(
            f"refusing to write generated tests outside workspace or temp: {resolved}"
        )

    resolved.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for index, artifact in enumerate(generate_regression_artifacts(bundle)):
        failure_mode = "".join(
            ch if ch.isalnum() or ch in {"_", "-"} else "_"
            for ch in str(artifact["failure_mode"])
        )[:80]
        json_path = resolved / f"regression_{index}_{failure_mode}.json"
        # Ensure no path traversal via failure_mode.
        if json_path.resolve().parent != resolved:
            raise ValueError(f"unsafe generated test path: {json_path}")
        json_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        written.append(json_path)
        pytest_source = artifact.get("pytest_source")
        if pytest_source:
            py_path = resolved / f"regression_{index}_{failure_mode}.py"
            if py_path.resolve().parent != resolved:
                raise ValueError(f"unsafe generated test path: {py_path}")
            header = (
                "# Generated by OVK. Artifact only — not auto-executed.\n"
                "# Run under explicit pytest policy if desired.\n"
            )
            py_path.write_text(header + pytest_source, encoding="utf-8")
            written.append(py_path)
    return written
