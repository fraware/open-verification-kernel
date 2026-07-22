"""Repository context builder for OVK orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from ovk.core.change_detection import detect_change_surfaces
from ovk.core.check_metadata import load_required_check_metadata
from ovk.core.github_event import load_github_event_metadata, metadata_to_self_protection_defaults
from ovk.core.json_io import read_json_file
from ovk.core.router import VerificationBudget
from ovk.paths import schema_path


@dataclass
class RepositoryContext:
    """Typed repository context for planning and execution."""

    repo: str = "unknown/repo"
    head_sha: str = "unknown"
    base_sha: str | None = None
    actor_type: str = "unknown"
    changed_files: list[str] = field(default_factory=list)
    surfaces: list[dict[str, Any]] = field(default_factory=list)
    branch_metadata: dict[str, Any] = field(default_factory=dict)
    policy: dict[str, Any] = field(default_factory=dict)


def load_verification_policy(config_path: Path = Path(".verification/config.yml")) -> dict[str, Any]:
    """Load and validate policy knobs from `.verification/config.yml`.

    Policy controls fail closed: malformed YAML or schema-invalid settings raise
    a clear error instead of being reinterpreted by an ad-hoc fallback parser.
    """
    if not config_path.exists():
        return {
            "schema_version": "ovk.config.v1",
            "mode": "advisory",
            "default_on_unknown": "require_human_review",
        }

    import yaml

    try:
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise ValueError(f"invalid OVK verification policy YAML at {config_path}: {error}") from error
    if not isinstance(loaded, dict):
        raise ValueError(f"OVK verification policy at {config_path} must contain a YAML mapping")

    policy_schema_path = schema_path("verification.config.schema.json")
    if not policy_schema_path.exists():
        raise ValueError(f"OVK verification policy schema is missing: {policy_schema_path}")
    schema = read_json_file(policy_schema_path)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(loaded), key=lambda item: list(item.path))
    if errors:
        formatted = []
        for error in errors:
            location = "/".join(str(part) for part in error.path) or "$"
            formatted.append(f"{location}: {error.message}")
        raise ValueError(
            f"OVK verification policy at {config_path} failed schema validation: " + "; ".join(formatted)
        )
    return loaded


def budget_from_policy(policy: dict[str, Any]) -> VerificationBudget:
    """Build a verification budget from repository policy."""
    budget_section = policy.get("budget", {})
    if not isinstance(budget_section, dict):
        budget_section = {}
    allowed = budget_section.get("allowed_backends") or policy.get("allowed_backends")
    denied = budget_section.get("denied_backends") or policy.get("denied_backends", [])
    allowed_set = frozenset(str(item) for item in allowed) if isinstance(allowed, (list, tuple)) else None
    denied_set = frozenset(str(item) for item in denied) if isinstance(denied, (list, tuple)) else frozenset()
    max_wall = float(budget_section.get("max_wall_time_seconds", policy.get("max_wall_time_seconds", 30.0)))
    max_memory = int(budget_section.get("max_memory_mb", policy.get("max_memory_mb", 512)))
    routing_section = policy.get("routing", {})
    prefer_deterministic = False
    if isinstance(routing_section, dict):
        prefer_deterministic = bool(routing_section.get("prefer_deterministic", False))
    return VerificationBudget(
        max_wall_time_seconds=max_wall,
        max_memory_mb=max_memory,
        allowed_backends=allowed_set,
        denied_backends=denied_set,
        prefer_deterministic=prefer_deterministic,
    )


def build_repository_context(
    *,
    changed_files: list[str] | None = None,
    github_event_path: Path | None = None,
    check_metadata_path: Path | None = None,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
) -> RepositoryContext:
    """Build repository context from PR metadata and changed files."""
    files = changed_files or []
    branch_metadata: dict[str, Any] = {}
    actor_type = "unknown"
    if github_event_path is not None and github_event_path.exists():
        github = load_github_event_metadata(github_event_path)
        defaults = metadata_to_self_protection_defaults(github)
        actor_type = str(defaults.get("actor_type", "unknown"))
        repo = github.repository or repo
        head_sha = github.head_sha or head_sha
        base_sha = github.base_sha or base_sha
        branch_metadata["github"] = defaults
    if check_metadata_path is not None and check_metadata_path.exists():
        branch_metadata.update(load_required_check_metadata(check_metadata_path))
    surfaces = [surface.__dict__ for surface in detect_change_surfaces(files)]
    return RepositoryContext(
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        actor_type=actor_type,
        changed_files=files,
        surfaces=surfaces,
        branch_metadata=branch_metadata,
        policy=load_verification_policy(),
    )
