"""Command-line interface for Open Verification Kernel."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from jsonschema import Draft202012Validator

from ovk.core.decision import decide
from ovk.core.models import EvidenceBundle

app = typer.Typer(help="Open Verification Kernel CLI")


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
def infer(
    base: Optional[str] = typer.Option(None, help="Base ref, for example origin/main."),
    head: Optional[str] = typer.Option(None, help="Head ref, for example HEAD."),
) -> None:
    """Placeholder for intent inference.

    Engineers should implement repository diff parsing here. For now this command documents the target CLI.
    """
    typer.echo(json.dumps({"base": base, "head": head, "intents": []}, indent=2))


if __name__ == "__main__":
    app()
