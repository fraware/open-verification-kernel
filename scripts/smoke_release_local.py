#!/usr/bin/env python
"""Run local OVK release smoke checks without GitHub Actions."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from ovk.adapters.ci_secrets.evidence import evaluate_ci_secrets_exposure
from ovk.adapters.deployment.evidence import evaluate_approval_state_machine
from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
from ovk.core.bundle import make_bundle
from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.json_io import read_json_file
from ovk.core.run_outputs import StandardOutputPaths, write_standard_run_outputs
from ovk.core.sprint1_runner import build_metadata_from_inputs, run_sprint1_self_protection
from scripts.check_release_metadata import main as check_release_metadata


def _write_lane_outputs(bundle, root: Path, prefix: str) -> None:
    write_standard_run_outputs(
        bundle,
        StandardOutputPaths(
            evidence=root / f"{prefix}-evidence.json",
            markdown=root / f"{prefix}-comment.md",
            attestation=root / f"{prefix}-attestation.json",
            manifest=root / f"{prefix}-manifest.json",
            quality_report=root / f"{prefix}-quality.json",
        ),
    )


def run_local_release_smoke() -> list[str]:
    """Run local release smoke checks and return failure messages."""
    failures: list[str] = []
    if check_release_metadata() != 0:
        failures.append("release metadata check failed")

    with TemporaryDirectory() as tmp:
        root = Path(tmp)

        authorization_data = read_json_file(Path("examples/auth_regression/input_admin_bypass.json"))
        authorization_evidence = evaluate_validated_authorization_path(
            authorization_data,
            repo="smoke/repo",
            head_sha="smoke-head",
        )
        authorization_bundle = make_bundle([authorization_evidence])
        _write_lane_outputs(authorization_bundle, root, "authorization")
        if authorization_bundle.decision.get("merge_recommendation") != "block":
            failures.append("authorization smoke check did not block expected fixture")

        infra_data = read_json_file(Path("examples/infrastructure_exposure/input_private_sensitive_resource.json"))
        infra_evidence = evaluate_infra_exposure(
            infra_data,
            repo="smoke/repo",
            head_sha="smoke-head",
        )
        infra_bundle = make_bundle([infra_evidence])
        _write_lane_outputs(infra_bundle, root, "infrastructure")
        if infra_bundle.decision.get("merge_recommendation") != "allow":
            failures.append("infrastructure smoke check did not allow expected fixture")

        self_protection_metadata = build_metadata_from_inputs(
            metadata_path=Path("examples/no_agent_self_approval/metadata_gate_removed.json"),
        )
        self_protection_result = run_sprint1_self_protection(
            metadata=self_protection_metadata,
            repo="smoke/repo",
            head_sha="smoke-head",
        )
        _write_lane_outputs(self_protection_result.bundle, root, "self-protection")
        if self_protection_result.recommendation != "block":
            failures.append("self-protection smoke check did not block expected fixture")

        ci_secrets_data = read_json_file(Path("examples/ci_secrets/input_secrets_safe.json"))
        ci_secrets_evidence = evaluate_ci_secrets_exposure(
            ci_secrets_data,
            repo="smoke/repo",
            head_sha="smoke-head",
        )
        ci_secrets_bundle = make_bundle([ci_secrets_evidence])
        _write_lane_outputs(ci_secrets_bundle, root, "ci-secrets")
        if ci_secrets_bundle.decision.get("merge_recommendation") != "allow":
            failures.append("ci-secrets smoke check did not allow expected fixture")

        deployment_data = read_json_file(Path("examples/deployment_state/input_valid_approval_path.json"))
        deployment_evidence = evaluate_approval_state_machine(
            deployment_data,
            repo="smoke/repo",
            head_sha="smoke-head",
        )
        deployment_bundle = make_bundle([deployment_evidence])
        _write_lane_outputs(deployment_bundle, root, "deployment")
        if deployment_bundle.decision.get("merge_recommendation") != "allow":
            failures.append("deployment smoke check did not allow expected fixture")

        expected = [
            "authorization-evidence.json",
            "authorization-comment.md",
            "authorization-attestation.json",
            "authorization-manifest.json",
            "authorization-quality.json",
            "infrastructure-evidence.json",
            "infrastructure-comment.md",
            "infrastructure-attestation.json",
            "infrastructure-manifest.json",
            "infrastructure-quality.json",
            "self-protection-evidence.json",
            "self-protection-comment.md",
            "self-protection-attestation.json",
            "self-protection-manifest.json",
            "self-protection-quality.json",
            "ci-secrets-evidence.json",
            "ci-secrets-comment.md",
            "ci-secrets-attestation.json",
            "ci-secrets-manifest.json",
            "ci-secrets-quality.json",
            "deployment-evidence.json",
            "deployment-comment.md",
            "deployment-attestation.json",
            "deployment-manifest.json",
            "deployment-quality.json",
        ]
        for name in expected:
            if not (root / name).exists():
                failures.append(f"missing smoke output: {name}")

        for prefix in ("authorization", "infrastructure", "self-protection", "ci-secrets", "deployment"):
            quality_path = root / f"{prefix}-quality.json"
            bundle_path = root / f"{prefix}-evidence.json"
            from ovk.core.models import EvidenceBundle

            bundle = EvidenceBundle.model_validate(read_json_file(bundle_path))
            report = build_evidence_quality_report(bundle)
            if not report.passed:
                failures.append(f"quality report failed for {prefix} lane")
            written = read_json_file(quality_path)
            if written.get("passed") is not True:
                failures.append(f"quality report on disk failed for {prefix} lane")

    return failures


def main() -> int:
    failures = run_local_release_smoke()
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print("OVK local release smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
