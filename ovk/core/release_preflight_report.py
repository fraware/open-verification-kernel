"""Run OVK release preflight checks with a structured report."""

from __future__ import annotations

import argparse
from pathlib import Path

from ovk.core.bench import run_formal_pr_bench
from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.json_io import read_json_file, write_json_file
from ovk.core.models import EvidenceBundle
from ovk.core.preflight import PreflightReport, check_from_exit_code, check_from_failures
from ovk.paths import ensure_repo_on_path, resource_path


def _check_multi_lane_manifest() -> list[str]:
    """Run the full MVP verification manifest end-to-end."""
    from tempfile import TemporaryDirectory

    from ovk.core.multi_lane import load_verification_manifest, manifest_material_paths, run_verification_manifest
    from ovk.core.release_bundle import ReleaseBundlePaths, verify_release_bundle, write_release_bundle

    manifest_path = resource_path("examples", "verification_manifests", "full_mvp.json")
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest = load_verification_manifest(manifest_path)
        bundle = run_verification_manifest(
            manifest,
            repo="smoke/repo",
            head_sha="smoke-head",
            root=manifest_path.parent,
        )
        write_release_bundle(
            bundle,
            ReleaseBundlePaths(
                root=root,
                materials=manifest_material_paths(manifest, manifest_path.parent),
            ),
        )
        failures = verify_release_bundle(root)
        if bundle.decision.get("merge_recommendation") != "allow":
            failures.append("multi-lane manifest smoke check did not allow expected fixtures")
        return failures


def _check_adversarial_quality_gate() -> list[str]:
    """Ensure forged bundles are rejected by the evidence quality gate."""
    bundle = EvidenceBundle.model_validate(
        read_json_file(resource_path("examples", "evidence_quality", "adversarial_allow_with_fail.json"))
    )
    report = build_evidence_quality_report(bundle)
    if report.passed:
        return ["adversarial evidence quality gate did not reject forged bundle"]
    return []


def _check_smoke_quality_reports() -> list[str]:
    """Re-run lane smoke outputs in a temp dir and verify quality reports pass."""
    from tempfile import TemporaryDirectory

    from ovk.adapters.infra.evidence import evaluate_infra_exposure
    from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
    from ovk.core.bundle import make_bundle
    from ovk.core.sprint1_runner import build_metadata_from_inputs, run_sprint1_self_protection

    failures: list[str] = []
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        lanes = [
            (
                "authorization",
                make_bundle(
                    [
                        evaluate_validated_authorization_path(
                            read_json_file(resource_path("examples", "auth_regression", "input_admin_protected.json")),
                            repo="smoke/repo",
                            head_sha="smoke-head",
                        )
                    ]
                ),
            ),
            (
                "infrastructure",
                make_bundle(
                    [
                        evaluate_infra_exposure(
                            read_json_file(
                                resource_path(
                                    "examples",
                                    "infrastructure_exposure",
                                    "input_private_sensitive_resource.json",
                                )
                            ),
                            repo="smoke/repo",
                            head_sha="smoke-head",
                        )
                    ]
                ),
            ),
            (
                "self-protection",
                run_sprint1_self_protection(
                    metadata=build_metadata_from_inputs(
                        metadata_path=resource_path(
                            "examples",
                            "no_agent_self_approval",
                            "input_gate_preserved.json",
                        ),
                    ),
                    repo="smoke/repo",
                    head_sha="smoke-head",
                ).bundle,
            ),
        ]
        for name, bundle in lanes:
            report = build_evidence_quality_report(bundle)
            if not report.passed:
                failures.append(f"evidence quality failed for {name} lane: {[i.message for i in report.issues]}")
            out = root / f"{name}-quality.json"
            write_json_file(out, report.to_dict())
            loaded = EvidenceBundle.model_validate(bundle.model_dump(mode="json"))
            if not build_evidence_quality_report(loaded).passed:
                failures.append(f"evidence quality invariant regression for {name} lane")
    return failures


def _check_template_validation() -> list[str]:
    """Validate all intent templates against the JSON schema."""
    ensure_repo_on_path()
    from scripts.validate_templates import validate_templates

    failures = validate_templates()
    if failures:
        return [f"template validation failed: {failures[0]} (+{len(failures) - 1} more)"]
    return []


def _check_formal_pr_bench() -> list[str]:
    """Run canonical FormalPR-Bench cases including extended categories."""
    scores, _leaderboard = run_formal_pr_bench(expanded=False, include_extended=True)
    failures = [score.case_id for score in scores if not score.passed]
    if failures:
        return [f"FormalPR-Bench failures: {', '.join(failures)}"]
    return []


def _check_pilot_program() -> list[str]:
    """Run all pilot manifests and require allow recommendations on pass fixtures."""
    from ovk.core.pilot import run_pilot_program

    report = run_pilot_program(pilot_dir=resource_path("examples", "pilot_repos"))
    failures: list[str] = []
    for result in report["results"]:
        if not result["passed"]:
            failures.append(
                f"pilot manifest {result['name']} did not allow: {result['merge_recommendation']}"
            )
    if report["manifests_passed"] != report["manifests_total"]:
        failures.append(
            f"pilot program passed {report['manifests_passed']}/{report['manifests_total']} manifests"
        )
    return failures


def _check_ovk_check_latency() -> list[str]:
    """Ensure multi-surface `ovk check` stays within the v1.0 CI latency budget."""
    import time

    from ovk.core.check import run_check

    diff_text = resource_path("examples", "multi_surface", "pr_combined.diff").read_text(encoding="utf-8")
    started = time.perf_counter()
    run_check(diff_text=diff_text, repo="smoke/repo", head_sha="smoke-head", use_cache=False)
    elapsed_ms = (time.perf_counter() - started) * 1000
    if elapsed_ms > 45000:
        return [f"ovk check latency budget exceeded: {elapsed_ms:.0f}ms > 45000ms"]
    return []


def build_release_preflight_report() -> PreflightReport:
    """Run release preflight checks and return a structured report."""
    ensure_repo_on_path()
    from scripts.check_command_surface import main as check_command_surface
    from scripts.check_release_metadata import main as check_release_metadata
    from scripts.smoke_release_local import run_local_release_smoke

    return PreflightReport(
        (
            check_from_exit_code("release_metadata", check_release_metadata(), "release metadata preflight failed"),
            check_from_exit_code("command_surface", check_command_surface(), "command surface preflight failed"),
            check_from_failures("local_release_smoke", run_local_release_smoke()),
            check_from_failures("evidence_quality", _check_smoke_quality_reports()),
            check_from_failures("adversarial_quality_gate", _check_adversarial_quality_gate()),
            check_from_failures("multi_lane_manifest", _check_multi_lane_manifest()),
            check_from_exit_code(
                "external_smoke_checklist",
                __import__("scripts.external_smoke_checklist", fromlist=["main"]).main(),
                "external smoke checklist failed",
            ),
            check_from_failures("ovk_check_latency", _check_ovk_check_latency()),
            check_from_failures("formal_pr_bench", _check_formal_pr_bench()),
            check_from_failures("template_validation", _check_template_validation()),
            check_from_failures("pilot_program", _check_pilot_program()),
        )
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run OVK structured release preflight checks")
    parser.add_argument("--output", type=Path, default=None, help="Optional JSON preflight report output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_release_preflight_report()
    if args.output is not None:
        write_json_file(args.output, report.to_dict())
    for failure in report.failures:
        print(failure)
    if not report.passed:
        return 1
    print("OVK structured release preflight checks passed")
    return 0
