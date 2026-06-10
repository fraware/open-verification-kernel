#!/usr/bin/env python
"""Checklist for external OVK Action consumer readiness."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.core.attestation_binding import verify_bundle_statement_binding
from ovk.core.attestation import bundle_to_statement
from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.json_io import read_json_file
from ovk.core.models import EvidenceBundle


ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_WORKFLOW = ROOT / ".github/workflows/external-validation.yml"
EXTERNAL_SCENARIOS = ROOT / "benchmarks/external_validation/scenarios.json"


def _validate_external_scenarios_schema(payload: dict) -> list[str]:
    """Validate the external validation scenarios catalog structure."""
    failures: list[str] = []
    if payload.get("schema_version") != "ovk.external_validation.scenarios.v1":
        failures.append("external scenarios schema_version must be ovk.external_validation.scenarios.v1")
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        return failures + ["external scenarios must include a non-empty scenarios list"]

    required_ids = {
        "check_strict_block",
        "check_advisory_allow",
        "mvp_manifest_allow",
        "forged_bundle_rejected",
    }
    seen_ids: set[str] = set()
    valid_kinds = {"action_check", "action_ci", "action_manifest", "quality_gate"}
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            failures.append(f"scenario[{index}] must be an object")
            continue
        scenario_id = scenario.get("id")
        if not isinstance(scenario_id, str) or not scenario_id:
            failures.append(f"scenario[{index}] missing non-empty id")
            continue
        if scenario_id in seen_ids:
            failures.append(f"duplicate scenario id: {scenario_id}")
        seen_ids.add(scenario_id)

        kind = scenario.get("kind")
        if kind not in valid_kinds:
            failures.append(f"scenario[{scenario_id}] has invalid kind: {kind}")
        expected_recommendation = scenario.get("expected_recommendation")
        if not isinstance(expected_recommendation, str) or not expected_recommendation:
            failures.append(f"scenario[{scenario_id}] missing expected_recommendation")
        expect_exit_code = scenario.get("expect_exit_code")
        if not isinstance(expect_exit_code, int):
            failures.append(f"scenario[{scenario_id}] expect_exit_code must be an integer")

        if kind in {"action_check", "action_ci", "action_manifest"}:
            mode = scenario.get("mode")
            if mode not in {"advisory", "strict"}:
                failures.append(f"scenario[{scenario_id}] mode must be advisory or strict")
        if kind == "action_check" and not isinstance(scenario.get("changed_files"), str):
            failures.append(f"scenario[{scenario_id}] missing changed_files path")
        if kind == "action_ci":
            if not isinstance(scenario.get("changed_files"), str):
                failures.append(f"scenario[{scenario_id}] missing changed_files path")
            if not isinstance(scenario.get("metadata"), str):
                failures.append(f"scenario[{scenario_id}] missing metadata path")
        if kind == "action_manifest" and not isinstance(scenario.get("verification_manifest"), str):
            failures.append(f"scenario[{scenario_id}] missing verification_manifest path")
        if kind == "quality_gate" and not isinstance(scenario.get("input_bundle"), str):
            failures.append(f"scenario[{scenario_id}] missing input_bundle path")

    missing = sorted(required_ids - seen_ids)
    if missing:
        failures.append(f"external scenarios missing required IDs: {', '.join(missing)}")
    return failures


def validate_external_validation_matrix() -> list[str]:
    """Dry-run validate external validation matrix workflow + scenario catalog."""
    failures: list[str] = []

    if not EXTERNAL_WORKFLOW.exists():
        failures.append("missing .github/workflows/external-validation.yml")
    else:
        workflow_text = EXTERNAL_WORKFLOW.read_text(encoding="utf-8")
        if "use-check" not in workflow_text:
            failures.append("external-validation workflow should reference use-check")
        if "workflow_dispatch" not in workflow_text:
            failures.append("external-validation workflow should support workflow_dispatch")
        if "schedule:" not in workflow_text:
            failures.append("external-validation workflow should include a weekly schedule")

    if not EXTERNAL_SCENARIOS.exists():
        failures.append("missing benchmarks/external_validation/scenarios.json")
    else:
        payload = json.loads(EXTERNAL_SCENARIOS.read_text(encoding="utf-8"))
        failures.extend(_validate_external_scenarios_schema(payload))

    return failures


def run_external_smoke_checklist() -> list[str]:
    """Return failures for the external consumer smoke checklist."""
    failures: list[str] = []

    workflow = ROOT / "examples/github_workflows/external_consumer.yml"
    if not workflow.exists():
        failures.append("missing examples/github_workflows/external_consumer.yml")
    else:
        text = workflow.read_text(encoding="utf-8")
        if "use-check" not in text:
            failures.append("external consumer workflow should exercise ovk check path")

    action = ROOT / "action.yml"
    action_text = action.read_text(encoding="utf-8")
    if 'default: "true"' not in action_text or "use-check" not in action_text:
        failures.append("action.yml should default to ovk check path")

    adversarial = ROOT / "examples/evidence_quality/adversarial_allow_with_fail.json"
    bundle = EvidenceBundle.model_validate(read_json_file(adversarial))
    if build_evidence_quality_report(bundle).passed:
        failures.append("adversarial forged bundle must fail quality gate")

    sha_mismatch = ROOT / "examples/evidence_quality/adversarial_sha_mismatch.json"
    if sha_mismatch.exists():
        mismatch_bundle = EvidenceBundle.model_validate(read_json_file(sha_mismatch))
        if build_evidence_quality_report(mismatch_bundle).passed:
            failures.append("adversarial SHA mismatch bundle must fail quality gate")

    from ovk.adapters.infra.evidence import evaluate_infra_exposure
    from ovk.adapters.infra.normalize import normalize_infra_input
    from ovk.core.bundle import make_bundle

    infra_input = normalize_infra_input(
        read_json_file(ROOT / "examples/infrastructure_exposure/input_private_sensitive_resource.json"),
        "infra",
    )
    evidence = evaluate_infra_exposure(infra_input, repo="smoke/repo", head_sha="abc123")
    valid_bundle = make_bundle([evidence])
    statement = bundle_to_statement(valid_bundle)
    if verify_bundle_statement_binding(valid_bundle, statement):
        failures.append("valid bundle must bind to its attestation statement")

    tampered = json.loads(json.dumps(statement))
    tampered["predicate"]["verification"]["bundle_digest"] = "forged"
    if not verify_bundle_statement_binding(valid_bundle, tampered):
        failures.append("tampered attestation digest must be detectable")

    failures.extend(validate_external_validation_matrix())

    return failures


def main() -> int:
    failures = run_external_smoke_checklist()
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print("OVK external smoke checklist passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
