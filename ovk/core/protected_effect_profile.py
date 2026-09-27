"""Governed repository profile for FastAPI Protected Effect extraction.

The profile is semantic authority: it declares which dependency guards authorize
which namespaced effects, which calls are protected sinks, how resource identity
and scope are projected, and which source paths participate in extraction.

For pull-request evaluation the exact base-revision profile is authoritative.
The workspace/head profile is a proposal only. A PR therefore cannot modify its
own extraction semantics and use those modified semantics to justify itself.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectProfile,
    ResourceOwnershipAssertionSemantics,
    ResourceScopeAssertionSemantics,
)
from ovk.core.bundle import content_digest
from ovk.core.schema_validation import load_json, require_schema_valid
from ovk.paths import schema_path


PROTECTED_EFFECT_PROFILE_REPOSITORY_PATH = (
    ".verification/protected-effects.fastapi.json"
)
PROTECTED_EFFECT_PROFILE_SCHEMA_VERSION = "ovk.protected_effect_profile.v1"


class ScopeAssertionConfig(BaseModel):
    acted_scope_arg: int = Field(default=0, ge=0)
    authorized_resource_arg: int = Field(default=1, ge=0)
    acted_scope_attribute: str = "workspace_id"

    @field_validator("acted_scope_attribute")
    @classmethod
    def _non_empty_attribute(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("acted_scope_attribute must be non-empty")
        return value


class OwnershipAssertionConfig(BaseModel):
    resource_identity_attribute: str
    owner_attribute: str
    principal_attribute: str
    authorized_effects: list[str]
    allow_missing_resource: bool = True
    truthy_when_present: bool = False

    @field_validator(
        "resource_identity_attribute",
        "owner_attribute",
        "principal_attribute",
    )
    @classmethod
    def _non_empty_semantic_field(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("ownership assertion semantic fields must be non-empty")
        return value

    @field_validator("authorized_effects")
    @classmethod
    def _authorized_effects_non_empty(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values if value.strip()]
        if not normalized:
            raise ValueError("ownership assertion authorized_effects must be non-empty")
        if len(normalized) != len(set(normalized)):
            raise ValueError("ownership assertion authorized_effects must be unique")
        return normalized


class ProtectedEffectProfileConfig(BaseModel):
    """Repository-declared semantics for the supported FastAPI assurance profile."""

    schema_version: Literal["ovk.protected_effect_profile.v1"] = (
        "ovk.protected_effect_profile.v1"
    )
    profile_type: Literal["fastapi_dependency_effects_v1"] = (
        "fastapi_dependency_effects_v1"
    )

    source_paths: list[str]
    max_files: int = Field(default=500, ge=1, le=5000)
    max_total_bytes: int = Field(
        default=5_000_000,
        ge=1024,
        le=50_000_000,
    )

    sink_effects: dict[str, str]
    sink_identity_args: dict[str, int] = Field(default_factory=dict)
    sink_scope_keywords: dict[str, str] = Field(default_factory=dict)
    sink_missing_scope_unconstrained: list[str] = Field(default_factory=list)
    scope_assertions: dict[str, ScopeAssertionConfig] = Field(
        default_factory=dict
    )
    ownership_assertions: dict[str, OwnershipAssertionConfig] = Field(
        default_factory=dict
    )
    sink_contracts: dict[str, str] = Field(default_factory=dict)
    sink_contract_scope_attributes: dict[str, str] = Field(default_factory=dict)
    sink_contract_identity_attributes: dict[str, str] = Field(
        default_factory=dict
    )

    sink_binding_relations: dict[
        str,
        Literal["equal", "same_tenant", "custom"],
    ] = Field(default_factory=dict)
    sink_binding_authorized_projections: dict[
        str,
        Literal["identity", "scope", "attribute"],
    ] = Field(default_factory=dict)
    sink_binding_acted_projections: dict[
        str,
        Literal["identity", "scope", "attribute"],
    ] = Field(default_factory=dict)
    sink_binding_authorized_attributes: dict[str, str] = Field(
        default_factory=dict
    )
    sink_binding_acted_attributes: dict[str, str] = Field(default_factory=dict)

    dependency_guard_resources: dict[str, str] = Field(default_factory=dict)
    dependency_guard_effects: dict[str, list[str]] = Field(default_factory=dict)
    principal_parameter: str = "user"

    @field_validator("source_paths")
    @classmethod
    def _source_paths_non_empty(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values if value.strip()]
        if not normalized:
            raise ValueError("source_paths must contain at least one path pattern")
        if len(normalized) != len(set(normalized)):
            raise ValueError("source_paths must be unique")
        for pattern in normalized:
            if pattern.startswith("/") or ".." in PurePosixPath(pattern).parts:
                raise ValueError(
                    "source_paths must be repository-relative and cannot contain '..'"
                )
        return normalized

    @field_validator("sink_effects")
    @classmethod
    def _non_empty_mapping(
        cls,
        value: dict[str, str],
    ) -> dict[str, str]:
        if not value:
            raise ValueError("required profile mappings must be non-empty")
        normalized: dict[str, str] = {}
        for key, item in value.items():
            key = str(key).strip()
            item = str(item).strip()
            if not key or not item:
                raise ValueError("profile mapping keys and values must be non-empty")
            normalized[key] = item
        return normalized

    @field_validator("principal_parameter")
    @classmethod
    def _principal_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("principal_parameter must be non-empty")
        return value

    @model_validator(mode="after")
    def _validate_semantic_references(self) -> "ProtectedEffectProfileConfig":
        sink_keys = set(self.sink_effects)
        per_sink_maps = {
            "sink_identity_args": set(self.sink_identity_args),
            "sink_scope_keywords": set(self.sink_scope_keywords),
            "sink_missing_scope_unconstrained": set(
                self.sink_missing_scope_unconstrained
            ),
            "sink_contracts": set(self.sink_contracts),
            "sink_contract_scope_attributes": set(
                self.sink_contract_scope_attributes
            ),
            "sink_contract_identity_attributes": set(
                self.sink_contract_identity_attributes
            ),
            "sink_binding_relations": set(self.sink_binding_relations),
            "sink_binding_authorized_projections": set(
                self.sink_binding_authorized_projections
            ),
            "sink_binding_acted_projections": set(
                self.sink_binding_acted_projections
            ),
            "sink_binding_authorized_attributes": set(
                self.sink_binding_authorized_attributes
            ),
            "sink_binding_acted_attributes": set(
                self.sink_binding_acted_attributes
            ),
        }
        for label, keys in per_sink_maps.items():
            unknown = sorted(keys - sink_keys)
            if unknown:
                raise ValueError(
                    f"{label} references unknown sink keys: "
                    + ", ".join(unknown)
                )

        modeled_effects = set(self.sink_effects.values())
        for assertion_key, assertion in self.ownership_assertions.items():
            if not assertion_key.strip():
                raise ValueError("ownership assertion keys must be non-empty")
            unknown_effects = sorted(
                set(assertion.authorized_effects) - modeled_effects
            )
            if unknown_effects:
                raise ValueError(
                    f"ownership assertion {assertion_key} authorizes effects "
                    "absent from sink_effects: "
                    + ", ".join(unknown_effects)
                )
        for dependency, effects in self.dependency_guard_effects.items():
            if dependency not in self.dependency_guard_resources:
                raise ValueError(
                    "dependency_guard_effects references undeclared guard: "
                    + dependency
                )
            if not effects:
                raise ValueError(
                    "dependency_guard_effects values must be non-empty"
                )
            unknown_effects = sorted(set(effects) - modeled_effects)
            if unknown_effects:
                raise ValueError(
                    f"dependency {dependency} authorizes effects absent from "
                    "sink_effects: "
                    + ", ".join(unknown_effects)
                )

        for sink, projection in self.sink_binding_authorized_projections.items():
            if (
                projection == "attribute"
                and sink not in self.sink_binding_authorized_attributes
            ):
                raise ValueError(
                    f"authorized attribute projection for {sink} requires "
                    "sink_binding_authorized_attributes"
                )
        for sink, projection in self.sink_binding_acted_projections.items():
            if (
                projection == "attribute"
                and sink not in self.sink_binding_acted_attributes
            ):
                raise ValueError(
                    f"acted attribute projection for {sink} requires "
                    "sink_binding_acted_attributes"
                )
        return self

    def canonical_payload(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload["source_paths"] = sorted(payload["source_paths"])
        payload["sink_missing_scope_unconstrained"] = sorted(
            payload["sink_missing_scope_unconstrained"]
        )
        payload["ownership_assertions"] = {
            key: {
                **value,
                "authorized_effects": sorted(value["authorized_effects"]),
            }
            for key, value in sorted(payload["ownership_assertions"].items())
        }
        payload["dependency_guard_effects"] = {
            key: sorted(values)
            for key, values in sorted(
                payload["dependency_guard_effects"].items()
            )
        }
        return payload

    @property
    def profile_digest(self) -> str:
        return content_digest(self.canonical_payload())

    def runtime_profile(self) -> FastApiDependencyEffectProfile:
        return FastApiDependencyEffectProfile(
            sink_effects=dict(self.sink_effects),
            sink_identity_args=dict(self.sink_identity_args),
            sink_scope_keywords=dict(self.sink_scope_keywords),
            sink_missing_scope_unconstrained=frozenset(
                self.sink_missing_scope_unconstrained
            ),
            scope_assertions={
                key: ResourceScopeAssertionSemantics(
                    acted_scope_arg=value.acted_scope_arg,
                    authorized_resource_arg=value.authorized_resource_arg,
                    acted_scope_attribute=value.acted_scope_attribute,
                )
                for key, value in self.scope_assertions.items()
            },
            ownership_assertions={
                key: ResourceOwnershipAssertionSemantics(
                    resource_identity_attribute=value.resource_identity_attribute,
                    owner_attribute=value.owner_attribute,
                    principal_attribute=value.principal_attribute,
                    authorized_effects=tuple(value.authorized_effects),
                    allow_missing_resource=value.allow_missing_resource,
                    truthy_when_present=value.truthy_when_present,
                )
                for key, value in self.ownership_assertions.items()
            },
            sink_contracts=dict(self.sink_contracts),
            sink_contract_scope_attributes=dict(
                self.sink_contract_scope_attributes
            ),
            sink_contract_identity_attributes=dict(
                self.sink_contract_identity_attributes
            ),
            sink_binding_relations=dict(self.sink_binding_relations),
            sink_binding_authorized_projections=dict(
                self.sink_binding_authorized_projections
            ),
            sink_binding_acted_projections=dict(
                self.sink_binding_acted_projections
            ),
            sink_binding_authorized_attributes=dict(
                self.sink_binding_authorized_attributes
            ),
            sink_binding_acted_attributes=dict(
                self.sink_binding_acted_attributes
            ),
            dependency_guard_resources=dict(self.dependency_guard_resources),
            dependency_guard_effects={
                key: tuple(values)
                for key, values in self.dependency_guard_effects.items()
            },
            principal_parameter=self.principal_parameter,
        )


class GovernedProtectedEffectProfileContext(BaseModel):
    """Trusted active profile plus separately reviewed workspace proposal."""

    repository_path: str = PROTECTED_EFFECT_PROFILE_REPOSITORY_PATH
    base_sha: str | None = None
    active_source: Literal[
        "workspace_local",
        "base_revision",
        "base_absent",
        "unavailable",
    ]
    active_profile: ProtectedEffectProfileConfig | None = None
    active_revision: str | None = None
    profile_available: bool

    proposed_profile: ProtectedEffectProfileConfig | None = None
    proposal_valid: bool
    proposal_error: str | None = None

    profile_path_touched: bool = False
    semantic_profile_changed: bool | None = None
    change_detection_mismatch: bool = False
    governance_review_required: bool = False
    warning: str | None = None

    def require_active_profile(self) -> ProtectedEffectProfileConfig:
        if not self.profile_available or self.active_profile is None:
            raise ValueError("trusted Protected Effect profile is unavailable")
        return self.active_profile


def _validate_profile_mapping(
    loaded: object,
    *,
    source: str,
) -> ProtectedEffectProfileConfig:
    if not isinstance(loaded, dict):
        raise ValueError(
            f"OVK Protected Effect profile from {source} must contain a JSON object"
        )
    profile_schema_path = schema_path("protected_effect_profile.schema.json")
    if not profile_schema_path.exists():
        raise ValueError(
            f"OVK Protected Effect profile schema is missing: {profile_schema_path}"
        )
    require_schema_valid(
        loaded,
        load_json(profile_schema_path),
        context=f"OVK Protected Effect profile from {source}",
    )
    try:
        return ProtectedEffectProfileConfig.model_validate(loaded)
    except Exception as error:
        raise ValueError(
            f"OVK Protected Effect profile from {source} failed typed validation: "
            f"{error}"
        ) from error


def parse_protected_effect_profile_text(
    text: str,
    *,
    source: str,
) -> ProtectedEffectProfileConfig:
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"invalid OVK Protected Effect profile JSON from {source}: {error}"
        ) from error
    return _validate_profile_mapping(loaded, source=source)


def load_protected_effect_profile(
    profile_path: Path = Path(PROTECTED_EFFECT_PROFILE_REPOSITORY_PATH),
) -> ProtectedEffectProfileConfig | None:
    if not profile_path.exists():
        return None
    return parse_protected_effect_profile_text(
        profile_path.read_text(encoding="utf-8"),
        source=str(profile_path),
    )


def _repository_path_matches(
    changed_files: list[str],
    target: Path,
) -> bool:
    absolute_target = target.as_posix().lstrip("./")
    relative_target = PROTECTED_EFFECT_PROFILE_REPOSITORY_PATH.lstrip("./")
    for path in changed_files:
        normalized = str(path).replace("\\", "/").lstrip("./")
        if normalized in {absolute_target, relative_target}:
            return True
        if normalized.endswith("/" + relative_target):
            return True
    return False


def _run_git(args: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _load_base_profile(
    *,
    base_sha: str,
    profile_path: Path,
) -> tuple[
    Literal["base_revision", "base_absent", "unavailable"],
    ProtectedEffectProfileConfig | None,
    str | None,
]:
    commit_check = _run_git(
        ["git", "cat-file", "-e", f"{base_sha}^{{commit}}"]
    )
    if commit_check is None or commit_check.returncode != 0:
        return (
            "unavailable",
            None,
            "base revision is unavailable for Protected Effect profile governance",
        )

    repository_path = profile_path.as_posix()
    path_check = _run_git(
        ["git", "cat-file", "-e", f"{base_sha}:{repository_path}"]
    )
    if path_check is None:
        return (
            "unavailable",
            None,
            "could not determine whether the base Protected Effect profile exists",
        )
    if path_check.returncode != 0:
        return "base_absent", None, None

    completed = _run_git(
        ["git", "show", f"{base_sha}:{repository_path}"]
    )
    if completed is None or completed.returncode != 0:
        return (
            "unavailable",
            None,
            "base Protected Effect profile exists but could not be read",
        )
    try:
        profile = parse_protected_effect_profile_text(
            completed.stdout,
            source=f"base revision {base_sha}:{repository_path}",
        )
    except ValueError as error:
        return (
            "unavailable",
            None,
            f"base Protected Effect profile is invalid: {error}",
        )
    return "base_revision", profile, None


def load_governed_protected_effect_profile_context(
    *,
    changed_files: list[str],
    base_sha: str | None,
    profile_path: Path = Path(PROTECTED_EFFECT_PROFILE_REPOSITORY_PATH),
) -> GovernedProtectedEffectProfileContext:
    """Load the trusted base profile and a separately governed head proposal."""

    touched = _repository_path_matches(changed_files, profile_path)
    try:
        proposed = load_protected_effect_profile(profile_path)
        proposal_valid = True
        proposal_error = None
    except ValueError as error:
        proposed = None
        proposal_valid = False
        proposal_error = str(error)

    if base_sha is None:
        if not proposal_valid or proposed is None:
            return GovernedProtectedEffectProfileContext(
                base_sha=None,
                active_source="unavailable",
                active_profile=None,
                profile_available=False,
                proposed_profile=proposed,
                proposal_valid=proposal_valid,
                proposal_error=proposal_error,
                profile_path_touched=touched,
                semantic_profile_changed=None,
                governance_review_required=touched or not proposal_valid,
                warning=(
                    "workspace Protected Effect profile is unavailable or invalid"
                ),
            )
        return GovernedProtectedEffectProfileContext(
            base_sha=None,
            active_source="workspace_local",
            active_profile=proposed,
            profile_available=True,
            proposed_profile=proposed,
            proposal_valid=True,
            profile_path_touched=touched,
            semantic_profile_changed=False,
            governance_review_required=touched,
        )

    active_source, active, base_warning = _load_base_profile(
        base_sha=base_sha,
        profile_path=profile_path,
    )
    if active_source == "unavailable":
        return GovernedProtectedEffectProfileContext(
            base_sha=base_sha,
            active_source="unavailable",
            active_profile=None,
            active_revision=base_sha,
            profile_available=False,
            proposed_profile=proposed,
            proposal_valid=proposal_valid,
            proposal_error=proposal_error,
            profile_path_touched=touched,
            semantic_profile_changed=None,
            governance_review_required=True,
            warning=base_warning,
        )

    if active is None:
        changed = proposed is not None or not proposal_valid
        return GovernedProtectedEffectProfileContext(
            base_sha=base_sha,
            active_source="base_absent",
            active_profile=None,
            active_revision=base_sha,
            profile_available=False,
            proposed_profile=proposed,
            proposal_valid=proposal_valid,
            proposal_error=proposal_error,
            profile_path_touched=touched,
            semantic_profile_changed=changed,
            governance_review_required=touched or changed,
            warning=(
                "no Protected Effect profile exists in the trusted base revision"
            ),
        )

    if not proposal_valid:
        return GovernedProtectedEffectProfileContext(
            base_sha=base_sha,
            active_source="base_revision",
            active_profile=active,
            active_revision=base_sha,
            profile_available=True,
            proposed_profile=None,
            proposal_valid=False,
            proposal_error=proposal_error,
            profile_path_touched=touched,
            semantic_profile_changed=True,
            governance_review_required=True,
            warning=(
                "head Protected Effect profile proposal is invalid; the trusted "
                "base profile remains active"
            ),
        )

    changed = (
        proposed is None
        or proposed.profile_digest != active.profile_digest
    )
    mismatch = changed and not touched
    warning = base_warning
    if mismatch:
        warning = (
            "base/head Protected Effect profiles differ although changed-files "
            "metadata does not list the profile path"
        )

    return GovernedProtectedEffectProfileContext(
        base_sha=base_sha,
        active_source="base_revision",
        active_profile=active,
        active_revision=base_sha,
        profile_available=True,
        proposed_profile=proposed,
        proposal_valid=True,
        profile_path_touched=touched,
        semantic_profile_changed=changed,
        change_detection_mismatch=mismatch,
        governance_review_required=touched or changed,
        warning=warning,
    )
