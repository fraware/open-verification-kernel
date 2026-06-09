"""Command-line interface for Open Verification Kernel."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from jsonschema import Draft202012Validator

from ovk.adapters.opa import evaluate_self_protection
from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
from ovk.core.attestation import bundle_to_statement
from ovk.core.bundle import make_bundle
from ovk.core.decision import decide
from ovk.core.models import EvidenceBundle
from ovk.core.render import render_bundle_markdown
from ovk.core.sprint1_runner import (
    build_metadata_from_inputs,
    run_sprint1_self_protection,
    write_sprint1_outputs,
)

app = typer.Typer(help="Open Verification Kernel CLI")


EXIT_CODES = {
    "allow": 0,
    "allow_with_warning": 0,
    "block": 1,
    "require_human_review": 2,
    "require_stronger_check": 2,
}


@app.command()
def init(path: Path = typer.Option(Path(".verification"), help="Verification directory to create.")) -> None:
    """Create a starter .verification directory."""
    path.mkdir(parents=True, exist_ok=True)
    for child in ["intents", "capabilities", "evidence", "counterexamples", "generated_tests", "memory"]:
        (path / child).mkdir(exist_ok=True)
    config = path / "config.yml"
    if not config.exists():
        config.write_text(
            "schema_version: ovk.config.v1\n"
            "mode: advisory\n"
            "default_on_unknown: require_human_review\n",
            encoding="utf-8",
        )
    typer.echo(f"Initialized {path}")


@app.command()
def validate(instance: Path, schema: Path) -> None:
    """Validate a JSON instance against a JSON schema."""
    instance_data = json.loads(instance.read_text(encoding="utf-8"))
    schema_data = json.loads(schema.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema_data)
    errors = sorted(validator.iter_errors(instance_data), key=lambda e: e.path)
    if errors:
        for error in errors:
            typer.echo(f"validation error at {list(error.path)}: {error.message}")
        raise typer.Exit(code=1)
    typer.echo("valid")


@app.command()
def decide_bundle(evidence_bundle: Path, enforce: bool = True) -> None:
    """Compute a merge recommendation for an evidence bundle."""
    data = json.loads(evidence_bundle.read_text(encoding="utf-8"))
    bundle = EvidenceBundle.model_validate(data)
    recommendation = decide(bundle, enforce=enforce)
    typer.echo(recommendation.value)


@app.command()
def render_pr_comment(evidence_bundle: Path, output: Optional[Path] = None) -> None:
    """Render an evidence bundle as pull-request Markdown."""
    data = json.loads(evidence_bundle.read_text(encoding="utf-8"))
    bundle = EvidenceBundle.model_validate(data)
    rendered = render_bundle_markdown(bundle)
    if output:
        output.write_text(rendered, encoding="utf-8")
    else:
        typer.echo(rendered)


@app.command()
def demo_self_protection(
    input_json: Path,
    output: Path = typer.Option(Path("ovk-evidence.json"), help="Evidence bundle output path."),
    markdown_output: Optional[Path] = typer.Option(None, help="Optional Markdown output."),
    repo: str = typer.Option("unknown/repo", help="Repository name for evidence subject."),
    head_sha: str = typer.Option("unknown", help="Head commit SHA."),
    enforce: bool = typer.Option(True, help="Use non-zero exits for non-allow recommendations."),
) -> None:
    """Run the first OVK demo and emit an evidence bundle."""
    data = json.loads(input_json.read_text(encoding="utf-8"))
    evidence = evaluate_self_protection(data, repo=repo, head_sha=head_sha)
    bundle = make_bundle([evidence])
    output.write_text(json.dumps(bundle.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
    if markdown_output:
        markdown_output.write_text(render_bundle_markdown(bundle), encoding="utf-8")
    recommendation = bundle.decision.get("merge_recommendation", "require_human_review")
    typer.echo(f"OVK recommendation: {recommendation}")
    if enforce:
        raise typer.Exit(code=EXIT_CODES.get(str(recommendation), 2))


@app.command()
def ci(
    metadata: Optional[Path] = typer.Option(None, help="Optional self-protection metadata JSON."),
    changed_files: Optional[Path] = typer.Option(None, help="Changed files as JSON, newline text, or diff."),
    check_metadata: Optional[Path] = typer.Option(None, help="Required-check metadata JSON."),
    github_event: Optional[Path] = typer.Option(None, help="Optional GitHub event payload JSON."),
    backend_strategy: str = typer.Option(
        "deterministic",
        help="Backend strategy: deterministic, opa, or both.",
    ),
    repo: str = typer.Option("unknown/repo", help="Repository name for evidence subject."),
    head_sha: str = typer.Option("unknown", help="Head commit SHA."),
    base_sha: Optional[str] = typer.Option(None, help="Base commit SHA."),
    evidence_output: Path = typer.Option(Path("ovk-evidence.json"), help="Evidence bundle output path."),
    markdown_output: Path = typer.Option(Path("ovk-pr-comment.md"), help="Markdown output path."),
    attestation_output: Path = typer.Option(Path("ovk-attestation.json"), help="Attestation output path."),
    advisory: bool = typer.Option(False, help="Write outputs and exit 0."),
) -> None:
    """Run the Sprint 1 self-protection CI path."""
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
    )
    typer.echo(f"OVK recommendation: {result.recommendation}")
    if not advisory:
        raise typer.Exit(code=EXIT_CODES.get(result.recommendation, 2))


@app.command()
def auth_obligation(
    input_json: Path,
    repo: str = typer.Option("unknown/repo", help="Repository name for evidence subject."),
    head_sha: str = typer.Option("unknown", help="Head commit SHA."),
    base_sha: Optional[str] = typer.Option(None, help="Base commit SHA."),
    evidence_output: Path = typer.Option(Path("ovk-auth-evidence.json"), help="Evidence bundle output path."),
    markdown_output: Path = typer.Option(Path("ovk-auth-comment.md"), help="Markdown output path."),
    attestation_output: Path = typer.Option(Path("ovk-auth-attestation.json"), help="Attestation output path."),
    advisory: bool = typer.Option(False, help="Write outputs and exit 0."),
) -> None:
    """Run the validated authorization obligation path."""
    data = json.loads(input_json.read_text(encoding="utf-8"))
    evidence = evaluate_validated_authorization_path(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
    )
    bundle = make_bundle([evidence])
    evidence_output.write_text(json.dumps(bundle.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
    markdown_output.write_text(render_bundle_markdown(bundle), encoding="utf-8")
    attestation_output.write_text(json.dumps(bundle_to_statement(bundle), indent=2) + "\n", encoding="utf-8")
    recommendation = str(bundle.decision.get("merge_recommendation", "require_human_review"))
    typer.echo(f"OVK authorization recommendation: {recommendation}")
    if not advisory:
        raise typer.Exit(code=EXIT_CODES.get(recommendation, 2))


@app.command()
def infer(
    base: Optional[str] = typer.Option(None, help="Base ref, for example origin/main."),
    head: Optional[str] = typer.Option(None, help="Head ref, for example HEAD."),
) -> None:
    """Placeholder for intent inference."""
    typer.echo(json.dumps({"base": base, "head": head, "intents": []}, indent=2))


if __name__ == "__main__":
    app()
