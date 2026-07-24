"""Repository context builder for OVK orchestration."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from ovk.core.backend_ids import normalize_allowed_backends, normalize_denied_backends
from ovk.core.change_detection import detect_change_surfaces
from ovk.core.check_metadata import load_required_check_metadata
from ovk.core.github_event import load_github_event_metadata, metadata_to_self_protection_defaults
from ovk.core.json_io import read_json_file
from ovk.core.router import VerificationBudget
from ovk.paths import schema_path

POLICY_REPOSITORY_PATH = ".verification/config.yml"
SAFE_UNTRUSTED_POLICY: dict[str, Any] = {
    "schema_version": "ovk.config.v1",
    "mode": "strict",
    "default_on_unknown": "block",
    "budget": {
        "allow_network": False,
        "allow_repository_write": False,
    },
    "routing": {
        "mode": "shadow",
        "strategy": "primary_with_optional_corroboration",
        "aggregation": "ovk.aggregate.fail_dominant.v1",
        "max_selected_backends": 1,
        "prefer_deterministic": True,
        "allow_fallback": False,
        "accept_partial_primary": False,
        "enforced_lanes": [],
    },
}


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


def _validate_policy_mapping(loaded: object, *, source: str) -> dict[str, Any]:
    if not isinstance(loaded, dict):
        raise ValueError(f"OVK verification policy from {source} must contain a YAML mapping")
    policy_schema_path = schema_path("verification.config.schema.json")
    if not policy_schema_path.exists():
        raise ValueError(f"OVK verification policy schema is missing: {policy_schema_path}")
    validator = Draft202012Validator(read_json_file(policy_schema_path))
    errors = sorted(validator.iter_errors(loaded), key=lambda item: list(item.path))
    if errors:
        formatted = []
        for error in errors:
            location = "/".join(str(part) for part in error.path) or "$"
            formatted.append(f"{location}: {error.message}")
        raise ValueError(f"OVK verification policy from {source} failed schema validation: " + "; ".join(formatted))
    return dict(loaded)


def _parse_policy_text(text: str, *, source: str) -> dict[str, Any]:
    import yaml

    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise ValueError(f"invalid OVK verification policy YAML from {source}: {error}") from error
    return _validate_policy_mapping(loaded, source=source)


def load_verification_policy(config_path: Path = Path(POLICY_REPOSITORY_PATH)) -> dict[str, Any]:
    """Load and validate policy knobs from `.verification/config.yml`."""
    if not config_path.exists():
        return {
            "schema_version": "ovk.config.v1",
            "mode": "advisory",
            "default_on_unknown": "require_human_review",
        }
    return _parse_policy_text(
        config_path.read_text(encoding="utf-8"),
        source=str(config_path),
    )


def _policy_changed(changed_files: list[str], config_path: Path) -> bool:
    normalized_target = config_path.as_posix().lstrip("./")
    return any(str(path).replace("\\", "/").lstrip("./") == normalized_target for path in changed_files)


def load_trusted_verification_policy(
    *,
    changed_files: list[str],
    base_sha: str | None,
    config_path: Path = Path(POLICY_REPOSITORY_PATH),
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load policy from a trusted source when the PR changes its own policy.

    A pull request must never govern its own verification through a modified
    `.verification/config.yml`. When that path changes, OVK reads the base
    revision with `git show`. If the base material is unavailable or invalid,
    a conservative built-in policy is used and the source is recorded.
    """
    if not _policy_changed(changed_files, config_path):
        return load_verification_policy(config_path), {
            "policy_source": "workspace",
            "policy_path": config_path.as_posix(),
        }

    if base_sha:
        try:
            completed = subprocess.run(
                ["git", "show", f"{base_sha}:{config_path.as_posix()}"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            completed = None
        if completed is not None and completed.returncode == 0 and completed.stdout.strip():
            try:
                policy = _parse_policy_text(
                    completed.stdout,
                    source=f"base revision {base_sha}:{config_path.as_posix()}",
                )
            except ValueError:
                policy = None
            if policy is not None:
                return policy, {
                    "policy_source": "base_revision",
                    "policy_revision": base_sha,
                    "policy_path": config_path.as_posix(),
                }

    return dict(SAFE_UNTRUSTED_POLICY), {
        "policy_source": "safe_builtin",
        "policy_revision": base_sha,
        "policy_path": config_path.as_posix(),
        "policy_warning": "pull request policy was not trusted for its own verification",
    }


def budget_from_policy(policy: dict[str, Any]) -> VerificationBudget:
    """Build a verification budget from repository policy."""
    budget_section = policy.get("budget", {})
    if not isinstance(budget_section, dict):
        budget_section = {}
    allowed_raw = budget_section.get("allowed_backends")
    if allowed_raw is None:
        allowed_raw = policy.get("allowed_backends")
    denied_raw = budget_section.get("denied_backends")
    if denied_raw is None:
        denied_raw = policy.get("denied_backends", [])
    allowed = normalize_allowed_backends(allowed_raw)
    denied = normalize_denied_backends(denied_raw)
    allowed_set = frozenset(allowed) if allowed is not None else None
    denied_set = frozenset(denied)
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
    """Build repository context from PR metadata and trusted policy materials."""
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
    policy, policy_metadata = load_trusted_verification_policy(
        changed_files=files,
        base_sha=base_sha,
    )
    branch_metadata["verification_policy"] = policy_metadata
    surfaces = [surface.__dict__ for surface in detect_change_surfaces(files)]
    return RepositoryContext(
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        actor_type=actor_type,
        changed_files=files,
        surfaces=surfaces,
        branch_metadata=branch_metadata,
        policy=policy,
    )
