#!/usr/bin/env python
"""Run local OVK release smoke checks without GitHub Actions."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
from ovk.core.bundle import make_bundle
from ovk.core.json_io import read_json_file
from ovk.core.run_outputs import StandardOutputPaths, write_standard_run_outputs
from scripts.check_release_metadata import main as check_release_metadata


def _write_lane_outputs(bundle, root: Path, prefix: str) -> None:
    write_standard_run_outputs(
        bundle,
        StandardOutputPaths(
            evidence=root / f"{prefix}-evidence.json",
            markdown=root / f"{prefix}-comment.md",
            attestation=root / f"{prefix}-attestation.json",
            manifest=root / f"{prefix}-manifest.json",
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

        expected = [
            "authorization-evidence.json",
            "authorization-comment.md",
            "authorization-attestation.json",
            "authorization-manifest.json",
            "infrastructure-evidence.json",
            "infrastructure-comment.md",
            "infrastructure-attestation.json",
            "infrastructure-manifest.json",
        ]
        for name in expected:
            if not (root / name).exists():
                failures.append(f"missing smoke output: {name}")
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
