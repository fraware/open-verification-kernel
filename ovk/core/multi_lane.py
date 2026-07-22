"""Multi-lane verification orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ovk.adapters.ci_secrets.evidence import evaluate_ci_secrets_exposure
from ovk.adapters.deployment.evidence import evaluate_approval_state_machine
from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.adapters.infra.normalize import normalize_infra_input
from ovk.adapters.infra.policy_config import load_policy
from ovk.adapters.opa import evaluate_self_protection
from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
from ovk.core.backend_fixture import evaluate_backend_fixture
from ovk.core.bundle import content_digest, make_bundle
from ovk.core.json_io import read_json_file
from ovk.core.models import EvidenceBundle, VerificationEvidence
from ovk.core.planner import plan_from_changed_files, plan_from_diff_text
from ovk.core.schema_validation import validate_against_schema
from ovk.core.self_protection_input import SelfProtectionMetadata, build_self_protection_input
from ovk.paths import schema_path


LANE_INPUT_SCHEMAS: dict[str, str] = {
    "ci_secrets": "ci_secrets.input.schema.json",
    "deployment": "deployment_state.input.schema.json",
    "self_protection": "self_protection.input.schema.json",
}


def _validate_lane_input(data: dict[str, Any], schema_name: str, *, lane: str) -> None:
    """Validate lane input against a registered JSON schema."""
    path = schema_path(schema_name)
    if not path.exists():
        raise ValueError(f"{lane} input schema is missing: {path}")
    schema = read_json_file(path)
    report = validate_against_schema(data, schema)
    if not report.valid:
        issues = "; ".join(
            f"{'/'.join(str(part) for part in issue.path) or '$'}: {issue.message}"
            for issue in report.issues
        )
        raise ValueError(f"{lane} input failed schema validation: {issues}")


LANE_ALIASES = {
    "self_protection": "self_protection",
    "agent-cannot-disable-own-ci-gate": "self_protection",
    "authorization": "authorization",
    "authorization_obligation": "authorization",
    "no-admin-route-bypass": "authorization",
    "infrastructure": "infrastructure",
    "infrastructure_exposure": "infrastructure",
    "no-public-sensitive-resource": "infrastructure",
    "ci_secrets": "ci_secrets",
    "ci_secrets_exposure": "ci_secrets",
    "no-secrets-in-untrusted-context": "ci_secrets",
    "deployment": "deployment",
    "deployment_approval_state": "deployment",
    "no-skipped-approval-state": "deployment",
    "backend": "backend",
}


def normalize_lane_name(lane: str) -> str:
    """Normalize lane aliases and intent IDs to canonical lane names."""
    return LANE_ALIASES.get(lane.strip(), lane.strip())


def evaluate_lane(
    lane: str,
    data: dict[str, Any],
    *,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
    input_format: str = "infra",
    policy_path: Path | None = None,
) -> VerificationEvidence:
    """Evaluate one verification lane and return evidence."""
    canonical = normalize_lane_name(lane)
    if input_format == "backend" or canonical == "backend":
        return evaluate_backend_fixture(data, repo=repo, head_sha=head_sha, base_sha=base_sha)
    if canonical == "self_protection":
        if "actor" in data and "before" in data:
            structured = data
        else:
            _validate_lane_input(data, LANE_INPUT_SCHEMAS["self_protection"], lane=canonical)
            structured = build_self_protection_input(
                SelfProtectionMetadata(
                    actor_type=str(data.get("actor_type", data.get("author_type", "ai_agent"))),
                    agent_id=str(data.get("agent_id", data.get("agent", "unknown"))),
                    task=str(data.get("task", "unknown")),
                    changed_files=[str(path) for path in data.get("changed_files", [])],
                    before_required_checks=data.get("before_required_checks"),
                    after_required_checks=data.get("after_required_checks"),
                    before_workflow_permissions=data.get("before_workflow_permissions"),
                    after_workflow_permissions=data.get("after_workflow_permissions"),
                    ovk_gate_name=str(data.get("ovk_gate_name", "ovk-verify")),
                )
            )
        _validate_lane_input(structured, LANE_INPUT_SCHEMAS["self_protection"], lane=canonical)
        return evaluate_self_protection(structured, repo=repo, head_sha=head_sha, base_sha=base_sha)
    if canonical == "authorization":
        return evaluate_validated_authorization_path(data, repo=repo, head_sha=head_sha, base_sha=base_sha)
    if canonical == "infrastructure":
        normalized = normalize_infra_input(data, input_format)
        return evaluate_infra_exposure(
            normalized,
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
            policy=load_policy(policy_path),
        )
    if canonical == "ci_secrets":
        _validate_lane_input(data, LANE_INPUT_SCHEMAS["ci_secrets"], lane=canonical)
        return evaluate_ci_secrets_exposure(data, repo=repo, head_sha=head_sha, base_sha=base_sha)
    if canonical == "deployment":
        _validate_lane_input(data, LANE_INPUT_SCHEMAS["deployment"], lane=canonical)
        return evaluate_approval_state_machine(data, repo=repo, head_sha=head_sha, base_sha=base_sha)
    raise ValueError(f"unsupported lane: {lane}")


MANIFEST_SCHEMA_PATH = schema_path("verification.manifest.schema.json")


def load_verification_manifest(path: Path, *, validate: bool = True) -> dict[str, Any]:
    """Load a multi-lane verification manifest."""
    manifest = read_json_file(path)
    if not isinstance(manifest.get("lanes"), list):
        raise ValueError("verification manifest must include a lanes array")
    if validate:
        if not MANIFEST_SCHEMA_PATH.exists():
            raise ValueError(f"verification manifest schema is missing: {MANIFEST_SCHEMA_PATH}")
        schema = read_json_file(MANIFEST_SCHEMA_PATH)
        report = validate_against_schema(manifest, schema)
        if not report.valid:
            issues = "; ".join(
                f"{'/'.join(str(part) for part in issue.path) or '$'}: {issue.message}"
                for issue in report.issues
            )
            raise ValueError(f"verification manifest failed schema validation: {issues}")
    return manifest


def _resolve_manifest_file(root: Path, value: str, *, field: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        raise ValueError(f"verification manifest {field} path must be relative: {value}")
    root_resolved = root.resolve()
    resolved = (root_resolved / candidate).resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as error:
        raise ValueError(f"verification manifest {field} path escapes manifest root: {value}") from error
    if not resolved.is_file():
        raise ValueError(f"verification manifest {field} file does not exist: {value}")
    return resolved


def manifest_material_paths(manifest: dict[str, Any], root: Path) -> list[Path]:
    """Return validated manifest input and policy material paths."""
    materials: list[Path] = []
    seen: set[Path] = set()
    for entry in manifest.get("lanes", []):
        if not isinstance(entry, dict):
            continue
        for field in ("input", "policy"):
            value = entry.get(field)
            if not value:
                continue
            path = _resolve_manifest_file(root, str(value), field=field)
            if path not in seen:
                materials.append(path)
                seen.add(path)
    return materials


def _evaluate_manifest_entry(
    entry: dict[str, Any],
    *,
    manifest_root: Path,
    repo: str,
    head_sha: str,
    base_sha: str | None,
) -> VerificationEvidence | None:
    lane = str(entry.get("lane", ""))
    input_value = entry.get("input")
    if not lane or not input_value:
        return None
    input_path = _resolve_manifest_file(manifest_root, str(input_value), field="input")
    policy_path = (
        _resolve_manifest_file(manifest_root, str(entry["policy"]), field="policy")
        if entry.get("policy")
        else None
    )
    data = read_json_file(input_path)
    evidence = evaluate_lane(
        lane,
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        input_format=str(entry.get("input_format", "infra")),
        policy_path=policy_path,
    )
    identity = {
        "lane": lane,
        "input": str(input_value),
        "input_format": str(entry.get("input_format", "infra")),
        "policy": entry.get("policy"),
    }
    return evidence.model_copy(
        update={"evidence_id": f"{evidence.evidence_id}-{content_digest(identity)[:12]}"}
    )


def run_verification_manifest(
    manifest: dict[str, Any],
    *,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
    root: Path | None = None,
    parallel: bool = True,
) -> EvidenceBundle:
    """Run all lanes in a verification manifest and return a combined bundle."""
    manifest_root = (root or Path(".")).resolve()
    entries = [entry for entry in manifest["lanes"] if isinstance(entry, dict)]
    evidence_items: list[VerificationEvidence] = []

    if parallel and len(entries) > 1:
        with ThreadPoolExecutor(max_workers=min(len(entries), 5)) as pool:
            futures = [
                pool.submit(
                    _evaluate_manifest_entry,
                    entry,
                    manifest_root=manifest_root,
                    repo=repo,
                    head_sha=head_sha,
                    base_sha=base_sha,
                )
                for entry in entries
            ]
            for future in futures:
                item = future.result()
                if item is not None:
                    evidence_items.append(item)
    else:
        for entry in entries:
            item = _evaluate_manifest_entry(
                entry,
                manifest_root=manifest_root,
                repo=repo,
                head_sha=head_sha,
                base_sha=base_sha,
            )
            if item is not None:
                evidence_items.append(item)

    if not evidence_items:
        raise ValueError("verification manifest produced no evidence")
    return make_bundle(evidence_items)


def plan_required_inputs(changed_files: list[str]) -> dict[str, Any]:
    """Map changed files to required lane inputs using planner output."""
    plan = plan_from_changed_files(changed_files)
    return _required_inputs_from_plan(plan)


def plan_required_inputs_from_diff(diff_text: str) -> dict[str, Any]:
    """Map a unified diff to required lane inputs, including workflow extractions."""
    plan = plan_from_diff_text(diff_text)
    return _required_inputs_from_plan(plan)


def _required_inputs_from_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Build the infer/plan payload from planner output."""
    payload: dict[str, Any] = {
        "changed_files": plan.get("changed_files", []),
        "candidate_intents": plan.get("candidate_intents", []),
        "required_lanes": [normalize_lane_name(intent) for intent in plan.get("candidate_intents", [])],
        "surfaces": plan.get("surfaces", []),
    }
    if plan.get("source"):
        payload["source"] = plan["source"]
    if plan.get("workflow_inputs"):
        payload["workflow_inputs"] = plan["workflow_inputs"]
    if plan.get("suggested_lane_inputs"):
        payload["suggested_lane_inputs"] = plan["suggested_lane_inputs"]
    return payload
