"""Typer CLI subgroup: ``ovk verifier …``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from ovk.assurance.errors import AssuranceError, EvidenceError, MutationError, PinError, ReplayError
from ovk.assurance.evidence_pack import validate_evidence_dir
from ovk.assurance.mutation import mutate_profile
from ovk.assurance.pcs_export import snapshot_to_verifier_profile
from ovk.assurance.registry import build_verifier_registry, describe_backend, lookup_backend
from ovk.assurance.replay import replay_invocation
from ovk.assurance.runner import load_json_mapping, run_assurance
from ovk.assurance.snapshot import ConfigurationSnapshot
from ovk.core.backend_registry import BackendRegistry

verifier_app = typer.Typer(help="Verifier-assurance commands (PCS-gated; opt-in).")


def _echo_json(payload: object) -> None:
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


def _registry_with_optional(adapter: object | None = None) -> BackendRegistry:
    registry = build_verifier_registry()
    if adapter is not None:
        if registry.get(getattr(adapter, "backend_id")) is None:
            registry.register(adapter)  # type: ignore[arg-type]
    return registry


@verifier_app.command("describe")
def describe(
    backend: str = typer.Option(..., "--backend", help="Backend id to describe."),
) -> None:
    """Print ordinary capability (and assurance summary when present)."""
    try:
        payload = describe_backend(backend)
    except AssuranceError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    _echo_json(payload)


@verifier_app.command("snapshot-config")
def snapshot_config(
    backend: str = typer.Option(..., "--backend", help="Assurance-capable backend id."),
    out: Path = typer.Option(..., "--out", help="Output path for sealed VerifierProfile.v1 JSON."),
    config: Optional[Path] = typer.Option(None, "--config", help="Optional config JSON."),
) -> None:
    """Snapshot configuration to a sealed VerifierProfile.v1 (fail closed if not assurance-capable)."""
    try:
        adapter = lookup_backend(backend)
        from ovk.assurance.capability import is_assurance_capable

        manifest = adapter.manifest()
        if not is_assurance_capable(manifest):
            raise AssuranceError(
                f"backend {backend!r} is not assurance_capable; snapshot-config refused"
            )
        cfg = load_json_mapping(config) if config is not None else {}
        snap = adapter.snapshot_config(cfg)  # type: ignore[attr-defined]
        if not isinstance(snap, ConfigurationSnapshot):
            snap = ConfigurationSnapshot.model_validate(snap)
        profile = snapshot_to_verifier_profile(snap)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        typer.echo(str(out))
    except (AssuranceError, PinError, AttributeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@verifier_app.command("run")
def run(
    backend: str = typer.Option(..., "--backend", help="Assurance-capable backend id."),
    input_path: Path = typer.Option(..., "--input", help="Input JSON for the verifier."),
    evidence_dir: Path = typer.Option(..., "--evidence-dir", help="Evidence pack output directory."),
    config: Optional[Path] = typer.Option(None, "--config", help="Optional config JSON."),
    profile: Optional[Path] = typer.Option(None, "--profile", help="Optional sealed VerifierProfile.v1."),
) -> None:
    """Run an assurance-capable verifier and write an evidence pack."""
    try:
        adapter = lookup_backend(backend)
        from ovk.assurance.capability import is_assurance_capable

        if not is_assurance_capable(adapter.manifest()):
            raise AssuranceError(f"backend {backend!r} is not assurance_capable; run refused")
        input_data = load_json_mapping(input_path)
        from ovk.assurance.adjudication import refuse_labels_in_verifier_input

        refuse_labels_in_verifier_input(input_data)
        cfg = load_json_mapping(config) if config is not None else {}
        sealed_profile = load_json_mapping(profile) if profile is not None else None
        outcome = run_assurance(
            adapter,
            input_data=input_data,
            config=cfg,
            evidence_dir=evidence_dir,
            profile=sealed_profile,
        )
        _echo_json(
            {
                "decision": outcome.decision,
                "execution_status": outcome.execution_status,
                "indeterminate_reason": outcome.indeterminate_reason,
                "evidence_dir": str(outcome.evidence_dir),
                "profile_digest": outcome.profile["integrity"]["artifact_digest"],
                "result_digest": outcome.result["integrity"]["artifact_digest"],
            }
        )
    except (AssuranceError, PinError, EvidenceError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@verifier_app.command("validate-evidence")
def validate_evidence(
    evidence_dir: Path = typer.Argument(..., help="Evidence pack directory."),
) -> None:
    """Validate an evidence pack layout and PCS artifacts."""
    try:
        report = validate_evidence_dir(evidence_dir)
        _echo_json(report)
    except (EvidenceError, PinError, AssuranceError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@verifier_app.command("replay")
def replay(
    invocation: Path = typer.Argument(..., help="VerifierInvocationRecord.v1 JSON path."),
    evidence_dir: Path = typer.Option(..., "--evidence-dir", help="Evidence pack directory for profile/input."),
    backend: Optional[str] = typer.Option(
        None,
        "--backend",
        help="Backend id used for deterministic rerun (required for matched/drifted rerun).",
    ),
) -> None:
    """Replay an invocation; fail closed on drift when claiming matched."""
    try:
        if backend is None:
            raise AssuranceError("replay requires --backend for deterministic rerun")
        adapter = lookup_backend(backend)
        report = replay_invocation(invocation, adapter=adapter, evidence_dir=evidence_dir)
        _echo_json(report)
        if report.get("replay_status") == "drifted":
            raise typer.Exit(code=1)
    except (ReplayError, AssuranceError, PinError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@verifier_app.command("mutate")
def mutate(
    profile: Path = typer.Option(..., "--profile", help="Base sealed VerifierProfile.v1."),
    mutation: str = typer.Option(..., "--mutation", help="Mutation class from verifier_assurance.defs."),
    out: Path = typer.Option(..., "--out", help="Output path for mutated profile JSON."),
    parameters: Optional[Path] = typer.Option(
        None, "--parameters", help="Optional JSON object of mutation parameters."
    ),
    production_profile_path: Optional[Path] = typer.Option(
        None,
        "--production-profile-path",
        help="Refuse if --out would overwrite this production profile path.",
    ),
    backend: Optional[str] = typer.Option(
        None, "--backend", help="Optional backend to constrain supported mutation dimensions."
    ),
) -> None:
    """Apply a typed mutation producing a NEW profile (never overwrite production)."""
    try:
        params = load_json_mapping(parameters) if parameters is not None else {}
        # Convenience: allow --mutation alter_timeout:5000 style via parameters file only.
        supported = None
        if backend is not None:
            adapter = lookup_backend(backend)
            if hasattr(adapter, "supported_mutation_dimensions"):
                supported = list(adapter.supported_mutation_dimensions())
            elif adapter.manifest().assurance is not None:
                supported = list(adapter.manifest().assurance.mutation_dimensions)
        mutated, manifest = mutate_profile(
            profile,
            mutation_class=mutation,
            parameters=params,
            out_path=out,
            production_profile_path=production_profile_path,
            supported_dimensions=supported,
        )
        _echo_json(
            {
                "mutated_profile_id": mutated["verifier_profile_id"],
                "mutated_digest": mutated["integrity"]["artifact_digest"],
                "mutation_id": manifest["mutation_id"],
                "out": str(out),
            }
        )
    except (MutationError, AssuranceError, PinError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
