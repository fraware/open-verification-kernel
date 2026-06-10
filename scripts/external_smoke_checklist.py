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
