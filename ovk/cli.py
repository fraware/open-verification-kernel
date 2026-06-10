"""Command-line interface for Open Verification Kernel."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from jsonschema import Draft202012Validator

from ovk.adapters.ci_secrets.evidence import evaluate_ci_secrets_exposure
from ovk.adapters.deployment.evidence import evaluate_approval_state_machine
from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.adapters.infra.normalize import normalize_infra_input
from ovk.adapters.infra.policy_config import load_policy
from ovk.adapters.opa import evaluate_self_protection
from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
from ovk.core.bundle import make_bundle
from ovk.core.changed_files import load_changed_files
from ovk.core.decision import decide
from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.exit_codes import exit_code_for_recommendation
from ovk.core.json_io import read_json_file, write_json_file
from ovk.core.models import EvidenceBundle, VerificationEvidence
from ovk.core.output_validation import validate_output_directory
from ovk.adapters.workflow.yaml_extract import workflow_path_to_ci_secrets_input
from ovk.core.diff_parser import is_unified_diff
from ovk.core.multi_lane import (
    load_verification_manifest,
    manifest_material_paths,
    plan_required_inputs,
    plan_required_inputs_from_diff,
    run_verification_manifest,
)
from ovk.core.planner import plan_from_changed_files, plan_from_diff_text
from ovk.core.release_bundle import ReleaseBundlePaths, verify_release_bundle, write_release_bundle
from ovk.core.render import render_bundle_markdown
from ovk.core.run_outputs import StandardOutputPaths, write_standard_run_outputs
from ovk.core.sprint1_runner import (
    build_metadata_from_inputs,
    run_sprint1_self_protection,
    write_sprint1_outputs,
)
from ovk.core.check import load_diff_or_changed_files, run_check
from ovk.core.context import build_repository_context
from ovk.core.counterexample_translator import write_generated_tests
from ovk.core.doctor import run_doctor
from ovk.core.repo_memory import record_run
from ovk.core.run import run_from_changed_files
from ovk.core.templates_cli import apply_template, list_templates, show_template

app = typer.Typer(help="Open Verification Kernel CLI")
template_app = typer.Typer(help="Verification intent template commands")
app.add_typer(template_app, name="template")


def _finish_lane(
    bundle: EvidenceBundle,
    *,
    label: str,
    advisory: bool,
    paths: StandardOutputPaths | None = None,
    evidence_output: Path | None = None,
    markdown_output: Path | None = None,
    attestation_output: Path | None = None,
    manifest_output: Path | None = None,
    quality_output: Path | None = None,
) -> None:
    if paths is None:
        paths = StandardOutputPaths(
            evidence=evidence_output or Path("ovk-evidence.json"),
            markdown=markdown_output or Path("ovk-pr-comment.md"),
            attestation=attestation_output or Path("ovk-attestation.json"),
            manifest=manifest_output,
            quality_report=quality_output,
        )
    write_standard_run_outputs(bundle, paths)
    recommendation = str(bundle.decision.get("merge_recommendation", "require_human_review"))
    typer.echo(f"OVK {label} recommendation: {recommendation}")
    if not advisory:
        raise typer.Exit(code=exit_code_for_recommendation(recommendation))


@app.command("init")
def init(path: Path = typer.Option(Path(".verification"), help="Verification directory to create.")) -> None:
    """Create a starter .verification directory."""
    path.mkdir(parents=True, exist_ok=True)
    for child in ["intents", "capabilities", "evidence", "counterexamples", "generated_tests", "memory", "cache"]:
        (path / child).mkdir(exist_ok=True)
    config = path / "config.yml"
    if not config.exists():
        config.write_text(
            "schema_version: ovk.config.v1\n"
            "mode: advisory\n"
            "default_on_unknown: require_human_review\n",
            encoding="utf-8",
        )
    manifest_example = Path("examples/verification_manifests/full_mvp.json")
    manifest_dest = path / "manifest.json"
    if manifest_example.exists() and not manifest_dest.exists():
        manifest_dest.write_text(manifest_example.read_text(encoding="utf-8"), encoding="utf-8")
    templates_index = path / "templates-index.json"
    if not templates_index.exists():
        write_json_file(templates_index, {"templates": list_templates()})
    typer.echo(f"Initialized {path}")


@app.command("validate")
def validate(instance: Path, schema: Path) -> None:
    """Validate a JSON instance against a JSON schema."""
    instance_data = read_json_file(instance)
    schema_data = read_json_file(schema)
    validator = Draft202012Validator(schema_data)
    errors = sorted(validator.iter_errors(instance_data), key=lambda e: e.path)
    if errors:
        for error in errors:
            typer.echo(f"validation error at {list(error.path)}: {error.message}")
        raise typer.Exit(code=1)
    typer.echo("valid")


@app.command("decide-bundle")
def decide_bundle(evidence_bundle: Path, enforce: bool = True) -> None:
    """Compute a merge recommendation for an evidence bundle."""
    bundle = EvidenceBundle.model_validate(read_json_file(evidence_bundle))
    recommendation = decide(bundle, enforce=enforce)
    typer.echo(recommendation.value)


@app.command("render-pr-comment")
def render_pr_comment(evidence_bundle: Path, output: Optional[Path] = None) -> None:
    """Render an evidence bundle as pull-request Markdown."""
    bundle = EvidenceBundle.model_validate(read_json_file(evidence_bundle))
    rendered = render_bundle_markdown(bundle)
    if output:
        output.write_text(rendered, encoding="utf-8")
    else:
        typer.echo(rendered)


@app.command("validate-outputs")
def validate_outputs_cmd(
    bundle_dir: Path = typer.Argument(..., help="Release bundle directory to validate."),
) -> None:
    """Validate generated JSON artifacts and manifest hashes in a bundle directory."""
    schema_failures = validate_output_directory(bundle_dir)
    manifest_failures = verify_release_bundle(bundle_dir)
    failures = schema_failures + manifest_failures
    for failure in failures:
        typer.echo(failure)
    if failures:
        raise typer.Exit(code=1)
    typer.echo("OVK output validation passed")


@app.command("evidence-quality")
def evidence_quality(
    evidence_bundle: Path,
    output: Optional[Path] = typer.Option(None, help="Optional quality report JSON output."),
) -> None:
    """Check evidence bundle invariants and emit a quality report."""
    bundle = EvidenceBundle.model_validate(read_json_file(evidence_bundle))
    report = build_evidence_quality_report(bundle)
    payload = report.to_dict()
    if output:
        write_json_file(output, payload)
    else:
        typer.echo(json.dumps(payload, indent=2))
    if not report.passed:
        raise typer.Exit(code=1)


@app.command("pilot")
def pilot_cmd(
    pilot_dir: Optional[Path] = typer.Option(None, help="Directory of pilot manifest JSON files."),
    output: Optional[Path] = typer.Option(None, help="Optional pilot report JSON output."),
    repo: str = typer.Option("pilot/repo"),
    head_sha: str = typer.Option("pilot-head"),
) -> None:
    """Run the OVK pilot program manifests and emit adoption metrics."""
    from ovk.core.pilot import PILOT_DIR, run_pilot_program
    from ovk.core.schema_validation import require_schema_valid

    report = run_pilot_program(pilot_dir or PILOT_DIR, repo=repo, head_sha=head_sha)
    from ovk.paths import schema_path as ovk_schema_path

    pilot_schema = ovk_schema_path("pilot.report.schema.json")
    if pilot_schema.exists():
        require_schema_valid(report, read_json_file(pilot_schema), context="pilot report")
    if output:
        write_json_file(output, report)
    else:
        typer.echo(json.dumps(report, indent=2))
    for result in report["results"]:
        status = "PASS" if result["passed"] else result["merge_recommendation"].upper()
        typer.echo(f"{result['name']}: {status} ({result['elapsed_ms']:.0f}ms, {result['lane_count']} lanes)")
    if report["manifests_passed"] != report["manifests_total"]:
        raise typer.Exit(code=1)


@app.command("bench")
def bench_cmd(
    expanded: bool = typer.Option(False, help="Score the 100-case expanded benchmark set."),
    no_extended: bool = typer.Option(False, help="Skip routing/adversarial/repair-loop cases."),
    leaderboard: Path = typer.Option(
        Path(".verification/formal-pr-bench-leaderboard.json"),
        help="Leaderboard JSON output path.",
    ),
) -> None:
    """Run FormalPR-Bench and write a multi-dimensional leaderboard artifact."""
    from ovk.core.bench import run_formal_pr_bench
    from ovk.core.schema_validation import require_schema_valid

    scores, report = run_formal_pr_bench(expanded=expanded, include_extended=not no_extended)
    leaderboard.parent.mkdir(parents=True, exist_ok=True)
    from ovk.paths import schema_path as ovk_schema_path

    leaderboard_schema = ovk_schema_path("formal_pr_bench.leaderboard.schema.json")
    if leaderboard_schema.exists():
        require_schema_valid(report, read_json_file(leaderboard_schema), context="leaderboard")
    write_json_file(leaderboard, report)
    failures = [score for score in scores if not score.passed]
    summary = report["summary"]
    typer.echo(
        f"FormalPR-Bench: {summary['cases_passed']}/{summary['cases_total']} passed "
        f"(p95 {report['timing_ms']['p95']:.0f}ms)"
    )
    typer.echo(f"Leaderboard written to {leaderboard}")
    if failures:
        for score in failures:
            typer.echo(f"FAIL {score.case_id}: {score.details}")
        raise typer.Exit(code=1)


@app.command("release-preflight")
def release_preflight(
    output: Optional[Path] = typer.Option(None, help="Optional structured preflight report JSON."),
) -> None:
    """Run local release preflight checks."""
    from ovk.core.release_preflight_report import build_release_preflight_report

    report = build_release_preflight_report()
    if output:
        write_json_file(output, report.to_dict())
    for failure in report.failures:
        typer.echo(failure)
    if not report.passed:
        raise typer.Exit(code=1)
    typer.echo("OVK release preflight checks passed")


@app.command("release-bundle")
def release_bundle(
    lane: str = typer.Option(..., help="Lane: authorization, infrastructure, self_protection, ci_secrets, deployment."),
    input_json: Path = typer.Option(..., "--input", help="Lane input JSON."),
    output_dir: Path = typer.Option(Path("ovk-release-bundle"), help="Output directory."),
    input_format: str = typer.Option(
        "infra",
        help="Infrastructure input format when lane=infrastructure: infra, terraform, kubernetes, graph.",
    ),
    policy: Optional[Path] = typer.Option(None, help="Infrastructure policy JSON."),
    repo: str = typer.Option("unknown/repo"),
    head_sha: str = typer.Option("unknown"),
    base_sha: Optional[str] = typer.Option(None),
) -> None:
    """Write a complete verifiable release bundle for a lane."""
    evidence = _evaluate_lane(lane, input_json, input_format=input_format, policy=policy, repo=repo, head_sha=head_sha, base_sha=base_sha)
    bundle = make_bundle([evidence])
    write_release_bundle(bundle, ReleaseBundlePaths(root=output_dir))
    failures = verify_release_bundle(output_dir)
    for failure in failures:
        typer.echo(failure)
    if failures:
        raise typer.Exit(code=1)
    typer.echo(f"Release bundle written to {output_dir}")


def _evaluate_lane(
    lane: str,
    input_json: Path,
    *,
    input_format: str = "infra",
    policy: Path | None = None,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
) -> VerificationEvidence:
    data = read_json_file(input_json)
    if lane == "authorization":
        return evaluate_validated_authorization_path(data, repo=repo, head_sha=head_sha, base_sha=base_sha)
    if lane == "infrastructure":
        normalized = normalize_infra_input(data, input_format)
        return evaluate_infra_exposure(normalized, repo=repo, head_sha=head_sha, base_sha=base_sha, policy=load_policy(policy))
    if lane == "self_protection":
        return evaluate_self_protection(data, repo=repo, head_sha=head_sha, base_sha=base_sha)
    if lane == "ci_secrets":
        return evaluate_ci_secrets_exposure(data, repo=repo, head_sha=head_sha, base_sha=base_sha)
    if lane == "deployment":
        return evaluate_approval_state_machine(data, repo=repo, head_sha=head_sha, base_sha=base_sha)
    raise typer.BadParameter(f"unsupported lane: {lane}")


@app.command("demo-self-protection")
def demo_self_protection(
    input_json: Path,
    output: Path = typer.Option(Path("ovk-evidence.json"), help="Evidence bundle output path."),
    markdown_output: Optional[Path] = typer.Option(None, help="Optional Markdown output."),
    repo: str = typer.Option("unknown/repo", help="Repository name for evidence subject."),
    head_sha: str = typer.Option("unknown", help="Head commit SHA."),
    enforce: bool = typer.Option(True, help="Use non-zero exits for non-allow recommendations."),
) -> None:
    """Run the first OVK demo and emit an evidence bundle."""
    data = read_json_file(input_json)
    evidence = evaluate_self_protection(data, repo=repo, head_sha=head_sha)
    bundle = make_bundle([evidence])
    output.write_text(json.dumps(bundle.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
    if markdown_output:
        markdown_output.write_text(render_bundle_markdown(bundle), encoding="utf-8")
    recommendation = bundle.decision.get("merge_recommendation", "require_human_review")
    typer.echo(f"OVK recommendation: {recommendation}")
    if enforce:
        raise typer.Exit(code=exit_code_for_recommendation(str(recommendation)))


@app.command("ci")
def ci(
    metadata: Optional[Path] = typer.Option(None, help="Optional self-protection metadata JSON."),
    changed_files: Optional[Path] = typer.Option(None, help="Changed files as JSON, newline text, or diff."),
    check_metadata: Optional[Path] = typer.Option(None, help="Required-check metadata JSON."),
    github_event: Optional[Path] = typer.Option(None, help="Optional GitHub event payload JSON."),
    backend_strategy: str = typer.Option("deterministic", help="Backend strategy: deterministic, opa, or both."),
    repo: str = typer.Option("unknown/repo", help="Repository name for evidence subject."),
    head_sha: str = typer.Option("unknown", help="Head commit SHA."),
    base_sha: Optional[str] = typer.Option(None, help="Base commit SHA."),
    evidence_output: Path = typer.Option(Path("ovk-evidence.json"), help="Evidence bundle output path."),
    markdown_output: Path = typer.Option(Path("ovk-pr-comment.md"), help="Markdown output path."),
    attestation_output: Path = typer.Option(Path("ovk-attestation.json"), help="Attestation output path."),
    manifest_output: Path = typer.Option(Path("ovk-artifact-manifest.json"), help="Artifact manifest output path."),
    quality_output: Path = typer.Option(Path("ovk-evidence-quality.json"), help="Evidence quality report output path."),
    advisory: bool = typer.Option(False, help="Write outputs and exit 0."),
) -> None:
    """Run the self-protection CI path."""
    normalized = build_metadata_from_inputs(
        metadata_path=metadata,
        changed_files_path=changed_files,
        check_metadata_path=check_metadata,
        github_event_path=github_event,
    )
    result = run_sprint1_self_protection(
        metadata=normalized,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        backend_strategy=backend_strategy,
    )
    write_sprint1_outputs(
        result,
        evidence_output=evidence_output,
        markdown_output=markdown_output,
        attestation_output=attestation_output,
        manifest_output=manifest_output,
        quality_output=quality_output,
    )
    typer.echo(f"OVK recommendation: {result.recommendation}")
    if not advisory:
        raise typer.Exit(code=exit_code_for_recommendation(result.recommendation))


@app.command("auth-obligation")
def auth_obligation(
    input_json: Path,
    repo: str = typer.Option("unknown/repo", help="Repository name for evidence subject."),
    head_sha: str = typer.Option("unknown", help="Head commit SHA."),
    base_sha: Optional[str] = typer.Option(None, help="Base commit SHA."),
    evidence_output: Path = typer.Option(Path("ovk-auth-evidence.json"), help="Evidence bundle output path."),
    markdown_output: Path = typer.Option(Path("ovk-auth-comment.md"), help="Markdown output path."),
    attestation_output: Path = typer.Option(Path("ovk-auth-attestation.json"), help="Attestation output path."),
    manifest_output: Path = typer.Option(Path("ovk-auth-artifact-manifest.json"), help="Artifact manifest output path."),
    quality_output: Path = typer.Option(Path("ovk-auth-evidence-quality.json"), help="Evidence quality report output path."),
    advisory: bool = typer.Option(False, help="Write outputs and exit 0."),
) -> None:
    """Run the validated authorization obligation path."""
    data = read_json_file(input_json)
    evidence = evaluate_validated_authorization_path(data, repo=repo, head_sha=head_sha, base_sha=base_sha)
    _finish_lane(
        make_bundle([evidence]),
        label="authorization",
        advisory=advisory,
        evidence_output=evidence_output,
        markdown_output=markdown_output,
        attestation_output=attestation_output,
        manifest_output=manifest_output,
        quality_output=quality_output,
    )


@app.command("infra-exposure")
def infra_exposure(
    input_json: Path,
    input_format: str = typer.Option("infra", help="Input format: infra, terraform, kubernetes, or graph."),
    policy: Optional[Path] = typer.Option(None, help="Optional infrastructure exposure policy JSON."),
    repo: str = typer.Option("unknown/repo", help="Repository name for evidence subject."),
    head_sha: str = typer.Option("unknown", help="Head commit SHA."),
    base_sha: Optional[str] = typer.Option(None, help="Base commit SHA."),
    evidence_output: Path = typer.Option(Path("ovk-infra-evidence.json"), help="Evidence bundle output path."),
    markdown_output: Path = typer.Option(Path("ovk-infra-comment.md"), help="Markdown output path."),
    attestation_output: Path = typer.Option(Path("ovk-infra-attestation.json"), help="Attestation output path."),
    manifest_output: Path = typer.Option(Path("ovk-infra-artifact-manifest.json"), help="Artifact manifest output path."),
    quality_output: Path = typer.Option(Path("ovk-infra-evidence-quality.json"), help="Evidence quality report output path."),
    advisory: bool = typer.Option(False, help="Write outputs and exit 0."),
) -> None:
    """Run the infrastructure exposure path."""
    data = normalize_infra_input(read_json_file(input_json), input_format)
    evidence = evaluate_infra_exposure(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        policy=load_policy(policy),
    )
    _finish_lane(
        make_bundle([evidence]),
        label="infrastructure",
        advisory=advisory,
        evidence_output=evidence_output,
        markdown_output=markdown_output,
        attestation_output=attestation_output,
        manifest_output=manifest_output,
        quality_output=quality_output,
    )


@app.command("ci-secrets")
def ci_secrets(
    input_json: Path,
    repo: str = typer.Option("unknown/repo"),
    head_sha: str = typer.Option("unknown"),
    base_sha: Optional[str] = typer.Option(None),
    evidence_output: Path = typer.Option(Path("ovk-ci-secrets-evidence.json")),
    markdown_output: Path = typer.Option(Path("ovk-ci-secrets-comment.md")),
    attestation_output: Path = typer.Option(Path("ovk-ci-secrets-attestation.json")),
    manifest_output: Path = typer.Option(Path("ovk-ci-secrets-artifact-manifest.json")),
    quality_output: Path = typer.Option(Path("ovk-ci-secrets-evidence-quality.json")),
    advisory: bool = typer.Option(False),
) -> None:
    """Run the CI secrets exposure path."""
    evidence = evaluate_ci_secrets_exposure(read_json_file(input_json), repo=repo, head_sha=head_sha, base_sha=base_sha)
    _finish_lane(
        make_bundle([evidence]),
        label="ci_secrets",
        advisory=advisory,
        evidence_output=evidence_output,
        markdown_output=markdown_output,
        attestation_output=attestation_output,
        manifest_output=manifest_output,
        quality_output=quality_output,
    )


@app.command("deployment-state")
def deployment_state(
    input_json: Path,
    repo: str = typer.Option("unknown/repo"),
    head_sha: str = typer.Option("unknown"),
    base_sha: Optional[str] = typer.Option(None),
    evidence_output: Path = typer.Option(Path("ovk-deployment-evidence.json")),
    markdown_output: Path = typer.Option(Path("ovk-deployment-comment.md")),
    attestation_output: Path = typer.Option(Path("ovk-deployment-attestation.json")),
    manifest_output: Path = typer.Option(Path("ovk-deployment-artifact-manifest.json")),
    quality_output: Path = typer.Option(Path("ovk-deployment-evidence-quality.json")),
    advisory: bool = typer.Option(False),
) -> None:
    """Run the deployment approval state machine path."""
    evidence = evaluate_approval_state_machine(read_json_file(input_json), repo=repo, head_sha=head_sha, base_sha=base_sha)
    _finish_lane(
        make_bundle([evidence]),
        label="deployment",
        advisory=advisory,
        evidence_output=evidence_output,
        markdown_output=markdown_output,
        attestation_output=attestation_output,
        manifest_output=manifest_output,
        quality_output=quality_output,
    )


@app.command("verify")
def verify(
    manifest: Path = typer.Option(..., help="Multi-lane verification manifest JSON."),
    output_dir: Path = typer.Option(Path("ovk-verify-bundle"), help="Release bundle output directory."),
    repo: Optional[str] = typer.Option(None, help="Repository override."),
    head_sha: Optional[str] = typer.Option(None, help="Head SHA override."),
    base_sha: Optional[str] = typer.Option(None, help="Base SHA override."),
    advisory: bool = typer.Option(False, help="Write outputs and exit 0."),
) -> None:
    """Run a multi-lane verification manifest and emit a signed release bundle."""
    manifest_data = load_verification_manifest(manifest)
    manifest_root = manifest.parent
    bundle = run_verification_manifest(
        manifest_data,
        repo=repo or str(manifest_data.get("repo", "unknown/repo")),
        head_sha=head_sha or str(manifest_data.get("head_sha", "unknown")),
        base_sha=base_sha or manifest_data.get("base_sha"),
        root=manifest_root,
    )
    write_release_bundle(
        bundle,
        ReleaseBundlePaths(
            root=output_dir,
            materials=manifest_material_paths(manifest_data, manifest_root),
        ),
    )
    failures = verify_release_bundle(output_dir)
    failures.extend(validate_output_directory(output_dir))
    for failure in failures:
        typer.echo(failure)
    if failures:
        raise typer.Exit(code=1)
    recommendation = str(bundle.decision.get("merge_recommendation", "require_human_review"))
    typer.echo(f"OVK multi-lane recommendation: {recommendation}")
    typer.echo(f"Release bundle written to {output_dir}")
    if not advisory:
        raise typer.Exit(code=exit_code_for_recommendation(recommendation))


@app.command("extract-workflow")
def extract_workflow(
    workflow: Path,
    output: Optional[Path] = typer.Option(None, help="Optional CI secrets lane input JSON output."),
    trust_context: str = typer.Option("untrusted_fork_pr"),
) -> None:
    """Extract a CI secrets lane input from GitHub Actions workflow YAML."""
    payload = workflow_path_to_ci_secrets_input(workflow, trust_context=trust_context)
    if output:
        write_json_file(output, payload)
    else:
        typer.echo(json.dumps(payload, indent=2))


def _changed_files_payload(changed_files: Optional[Path]) -> dict:
    """Build infer/plan payload from a changed-files fixture or unified diff."""
    if changed_files is None:
        return plan_required_inputs([])
    text = changed_files.read_text(encoding="utf-8")
    if is_unified_diff(text):
        return plan_required_inputs_from_diff(text)
    return plan_required_inputs(load_changed_files(changed_files))


def _verification_plan(changed_files: Optional[Path]) -> dict:
    """Build a full verification plan from changed-files input."""
    if changed_files is None:
        return plan_from_changed_files([])
    text = changed_files.read_text(encoding="utf-8")
    if is_unified_diff(text):
        return plan_from_diff_text(text)
    return plan_from_changed_files(load_changed_files(changed_files))


@app.command("infer")
def infer(
    changed_files: Optional[Path] = typer.Option(None, help="Changed files as JSON, newline text, or diff."),
) -> None:
    """Infer candidate verification intents from changed files."""
    typer.echo(json.dumps(_changed_files_payload(changed_files), indent=2))


@app.command("plan")
def plan(
    changed_files: Optional[Path] = typer.Option(None, help="Changed files as JSON, newline text, or diff."),
) -> None:
    """Create a verification plan from changed files."""
    typer.echo(json.dumps(_verification_plan(changed_files), indent=2))


@app.command("check")
def check(
    diff: Optional[Path] = typer.Option(None, "--diff", help="Unified diff or changed-files input."),
    changed_files: Optional[Path] = typer.Option(None, help="Alias for --diff."),
    github_event: Optional[Path] = typer.Option(None, help="GitHub event payload JSON."),
    check_metadata: Optional[Path] = typer.Option(None, help="Required-check metadata JSON."),
    metadata: Optional[Path] = typer.Option(None, help="Self-protection metadata JSON."),
    repo: str = typer.Option("unknown/repo"),
    head_sha: str = typer.Option("unknown"),
    base_sha: Optional[str] = typer.Option(None),
    output_dir: Path = typer.Option(Path("."), help="Directory for standard run outputs."),
    advisory: bool = typer.Option(False, help="Write outputs and exit 0."),
    strict: bool = typer.Option(False, help="Enforce non-zero exit codes (overrides advisory)."),
    no_cache: bool = typer.Option(False, help="Disable lane result cache."),
    format: str = typer.Option("md", help="Output format: md, json, or github."),
) -> None:
    """Infer, compile, and verify affected lanes for a PR diff."""
    enforce_exit = strict or not advisory
    input_path = diff or changed_files
    files, diff_text = load_diff_or_changed_files(input_path)
    meta = read_json_file(metadata) if metadata else None
    result = run_check(
        changed_files=files,
        diff_text=diff_text,
        metadata=meta,
        check_metadata_path=check_metadata,
        github_event_path=github_event,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        use_cache=not no_cache,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = StandardOutputPaths(
        evidence=output_dir / "ovk-evidence.json",
        markdown=output_dir / "ovk-pr-comment.md",
        attestation=output_dir / "ovk-attestation.json",
        manifest=output_dir / "ovk-artifact-manifest.json",
        quality_report=output_dir / "ovk-evidence-quality.json",
    )
    write_standard_run_outputs(result.bundle, paths)
    record_run(result.bundle.model_dump(mode="json"))
    recommendation = str(result.bundle.decision.get("merge_recommendation", "require_human_review"))
    typer.echo(f"OVK check recommendation: {recommendation} ({result.elapsed_ms:.0f}ms)")
    if format == "json":
        typer.echo(json.dumps(result.bundle.model_dump(mode="json"), indent=2))
    elif format != "md":
        typer.echo(result.markdown)
    else:
        typer.echo(result.markdown)
    if enforce_exit:
        raise typer.Exit(code=exit_code_for_recommendation(recommendation))


@app.command("doctor")
def doctor_cmd(
    verification_dir: Path = typer.Option(Path(".verification"), help="Verification directory to inspect."),
    output: Optional[Path] = typer.Option(None, help="Optional JSON report output."),
) -> None:
    """Validate local OVK environment and repository layout."""
    report = run_doctor(verification_dir=verification_dir)
    if output:
        write_json_file(output, report)
    else:
        typer.echo(json.dumps(report, indent=2))
    if not report["passed"]:
        raise typer.Exit(code=1)


@app.command("run")
def run_cmd(
    changed_files: Optional[Path] = typer.Option(None, help="Changed files as JSON, newline text, or diff."),
    plan_json: Optional[Path] = typer.Option(None, "--plan", help="Optional plan JSON from `ovk plan`."),
    github_event: Optional[Path] = typer.Option(None, help="GitHub event payload JSON."),
    check_metadata: Optional[Path] = typer.Option(None, help="Required-check metadata JSON."),
    repo: str = typer.Option("unknown/repo"),
    head_sha: str = typer.Option("unknown"),
    base_sha: Optional[str] = typer.Option(None),
    output_dir: Path = typer.Option(Path("."), help="Directory for standard run outputs."),
    advisory: bool = typer.Option(False, help="Write outputs and exit 0."),
) -> None:
    """Execute a verification plan with routing metadata."""
    files, diff_text = load_diff_or_changed_files(changed_files)
    context = build_repository_context(
        changed_files=files,
        github_event_path=github_event,
        check_metadata_path=check_metadata,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
    )
    if plan_json is not None:
        from ovk.core.run import run_from_plan_dict

        plan = read_json_file(plan_json)
        result = run_from_plan_dict(plan, context=context, diff_text=diff_text)
    else:
        result = run_from_changed_files(files, diff_text=diff_text, context=context)
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = StandardOutputPaths(
        evidence=output_dir / "ovk-evidence.json",
        markdown=output_dir / "ovk-pr-comment.md",
        attestation=output_dir / "ovk-attestation.json",
        manifest=output_dir / "ovk-artifact-manifest.json",
        quality_report=output_dir / "ovk-evidence-quality.json",
    )
    write_standard_run_outputs(result.bundle, paths)
    record_run(result.bundle.model_dump(mode="json"))
    recommendation = str(result.bundle.decision.get("merge_recommendation", "require_human_review"))
    typer.echo(f"OVK run recommendation: {recommendation} ({result.elapsed_ms:.0f}ms)")
    typer.echo(f"OVK run lanes: {sorted({item['lane'] for item in result.obligations})}")
    if not advisory:
        raise typer.Exit(code=exit_code_for_recommendation(recommendation))


@app.command("generate-test")
def generate_test(
    evidence_bundle: Path = typer.Option(..., "--evidence", help="Evidence bundle JSON."),
    output_dir: Path = typer.Option(Path(".verification/generated_tests"), help="Regression artifact output directory."),
) -> None:
    """Generate regression artifacts from bundle counterexamples."""
    bundle = EvidenceBundle.model_validate(read_json_file(evidence_bundle))
    written = write_generated_tests(bundle, output_dir)
    for path in written:
        typer.echo(str(path))


@template_app.command("list")
def template_list() -> None:
    """List available verification intent templates."""
    typer.echo(json.dumps(list_templates(), indent=2))


@template_app.command("show")
def template_show(path: Path) -> None:
    """Show one verification intent template."""
    typer.echo(json.dumps(show_template(path), indent=2))


@template_app.command("apply")
def template_apply(
    path: Path,
    destination: Path = typer.Option(Path(".verification/intents/applied.intent.json")),
) -> None:
    """Copy a template into `.verification/intents/`."""
    applied = apply_template(path, destination)
    typer.echo(f"Applied template to {applied}")


if __name__ == "__main__":
    app()
